package org.openeuler.sbom.manager.service.vul.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.openeuler.sbom.clients.ossindex.OssIndexClient;
import org.openeuler.sbom.clients.ossindex.model.ComponentReportElement;
import org.openeuler.sbom.clients.ossindex.model.OssIndexVulnerability;
import org.openeuler.sbom.manager.dao.ExternalVulRefRepository;
import org.openeuler.sbom.manager.dao.VulnerabilityRepository;
import org.openeuler.sbom.manager.model.ExternalPurlRef;
import org.openeuler.sbom.manager.model.ExternalVulRef;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.Sbom;
import org.openeuler.sbom.manager.model.VulRefSource;
import org.openeuler.sbom.manager.model.VulReference;
import org.openeuler.sbom.manager.model.VulScore;
import org.openeuler.sbom.manager.model.VulScoringSystem;
import org.openeuler.sbom.manager.model.VulSource;
import org.openeuler.sbom.manager.model.VulStatus;
import org.openeuler.sbom.manager.model.Vulnerability;
import org.openeuler.sbom.manager.model.spdx.ReferenceCategory;
import org.openeuler.sbom.manager.model.spdx.ReferenceType;
import org.openeuler.sbom.manager.service.vul.AbstractVulService;
import org.openeuler.sbom.manager.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Qualifier("OssIndexServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class OssIndexServiceImpl extends AbstractVulService {

    private static final Logger logger = LoggerFactory.getLogger(OssIndexServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 128;

    private static final Map<String, List<String>> TYPE_CONVERT_MAP = Map.of(
            "github", List.of("rpm", "maven", "pypi", "npm"),
            "gitee", List.of("rpm", "maven", "pypi", "npm"),
            "gitlab", List.of("rpm", "maven", "pypi", "npm")
    );

    @Autowired
    private OssIndexClient ossIndexClient;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Override
    public void persistExternalVulRefForSbom(Sbom sbom, Boolean blocking) {
        logger.info("Start to persistExternalVulRefForSbom from OssIndex for sbom {}", sbom.getId());

        List<ExternalPurlRef> externalPurlRefs = sbom.getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .toList();

        List<List<ExternalPurlRef>> chunks = ListUtils.partition(externalPurlRefs, BULK_REQUEST_SIZE);
        for (int i = 0; i < chunks.size(); i++) {
            logger.info("fetch vulnerabilities from OssIndex for purl chunk {}, total {}", i + 1, chunks.size());
            List<ExternalPurlRef> chunk = chunks.get(i);
            Map<ExternalPurlRef, List<String>> refToConvertedPurl = chunk.stream()
                    .collect(Collectors.toMap(Function.identity(), OssIndexServiceImpl::convertPackageType));
            List<String> purls = refToConvertedPurl.values().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toSet())
                    .stream().toList();
            ListUtils.partition(purls, BULK_REQUEST_SIZE).forEach(chunkPurl -> {
                try {
                    Mono<ComponentReportElement[]> mono = ossIndexClient.getComponentReport(chunkPurl);
                    if (blocking) {
                        persistExternalVulRef(mono.block(), refToConvertedPurl);
                    } else {
                        mono.subscribe(report -> persistExternalVulRef(report, refToConvertedPurl));
                    }
                } catch (Exception e) {
                    logger.error("failed to fetch vulnerabilities from OssIndex for sbom {}", sbom.getId());
                    reportVulFetchFailure(sbom.getId());
                    throw e;
                }
            });
        }

        logger.info("End to persistExternalVulRefForSbom from OssIndex for sbom {}", sbom.getId());
    }

    private static List<String> convertPackageType(ExternalPurlRef ref) {
        if (ReferenceCategory.PACKAGE_MANAGER.equals(ReferenceCategory.findReferenceCategory(ref.getCategory()))
                && TYPE_CONVERT_MAP.containsKey(ref.getPurl().getType())) {
            return TYPE_CONVERT_MAP.get(ref.getPurl().getType()).stream()
                    .map(type -> PurlUtil.convertPackageType(ref.getPurl(), type)).toList();
        }
        return List.of(PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize());
    }

    private void persistExternalVulRef(ComponentReportElement[] report, Map<ExternalPurlRef, List<String>> refToConvertedPurl) {
        if (Objects.isNull(report) || report.length == 0) {
            return;
        }

        Set<Pair<UUID, String>> externalVulRefExistence = new HashSet<>();
        refToConvertedPurl.forEach((ref, purls) -> Arrays.stream(report)
                .filter(element -> purls.contains(element.getCoordinates()))
                .map(ComponentReportElement::getVulnerabilities)
                .flatMap(List::stream)
                .forEach(vul -> {
                    if (StringUtils.isEmpty(vul.getCve())) {
                        return;
                    }

                    Vulnerability vulnerability = vulnerabilityRepository.saveAndFlush(persistVulnerability(vul));
                    if (externalVulRefExistence.contains(Pair.of(vulnerability.getId(), PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize()))) {
                        return;
                    }
                    Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional.ofNullable(ref.getPkg().getExternalVulRefs())
                            .orElse(new ArrayList<>())
                            .stream()
                            .collect(Collectors.toMap(it ->
                                            Pair.of(it.getVulnerability().getId(), PurlUtil.PackageUrlVoToPackageURL(it.getPurl()).canonicalize()),
                                    Function.identity()));
                    ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(
                            vulnerability.getId(), PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize()), new ExternalVulRef());
                    externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
                    externalVulRef.setType(ReferenceType.CVE.getType());
                    externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.AFFECTED.name()));
                    externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize()));
                    externalVulRef.setVulnerability(vulnerability);
                    externalVulRef.setPkg(ref.getPkg());
                    externalVulRefRepository.saveAndFlush(externalVulRef);
                    externalVulRefExistence.add(Pair.of(vulnerability.getId(), PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize()));
                }));
    }

    private Vulnerability persistVulnerability(OssIndexVulnerability ossIndexVulnerability) {
        Vulnerability vulnerability = vulnerabilityRepository.findByVulIdAndSource(
                ossIndexVulnerability.getCve(), VulSource.OSS_INDEX.name()).orElse(new Vulnerability());
        vulnerability.setVulId(ossIndexVulnerability.getCve());
        vulnerability.setType(ReferenceType.CVE.getType());
        vulnerability.setSource(VulSource.OSS_INDEX.name());
        vulnerability.setDescription(ossIndexVulnerability.getDescription());
        List<VulReference> vulReferences = persistVulReferences(vulnerability, ossIndexVulnerability);
        vulnerability.setVulReferences(vulReferences);
        List<VulScore> vulScores = persistVulScores(vulnerability, ossIndexVulnerability);
        vulnerability.setVulScores(vulScores);
        return vulnerability;
    }

    private List<VulReference> persistVulReferences(Vulnerability vulnerability, OssIndexVulnerability ossIndexVulnerability) {
        List<VulReference> vulReferences = new ArrayList<>();

        Map<Pair<String, String>, VulReference> existVulReferences = Optional.ofNullable(vulnerability.getVulReferences())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getSource(), it.getUrl()), Function.identity()));

        VulReference vulReference = existVulReferences.getOrDefault(
                Pair.of(VulRefSource.OSS_INDEX.name(), ossIndexVulnerability.getReference()), new VulReference());
        vulReference.setSource(VulRefSource.OSS_INDEX.name());
        vulReference.setUrl(ossIndexVulnerability.getReference());
        vulReference.setVulnerability(vulnerability);
        vulReferences.add(vulReference);

        ossIndexVulnerability.getExternalReferences().forEach(ref -> {
            VulRefSource source = VulRefSource.findVulRefSourceByHost(ref);
            if (Objects.nonNull(source)) {
                VulReference vul = existVulReferences.getOrDefault(Pair.of(source.name(), ref), new VulReference());
                vul.setSource(source.name());
                vul.setUrl(ref);
                vul.setVulnerability(vulnerability);
                vulReferences.add(vul);
            }
        });

        return vulReferences;
    }

    private List<VulScore> persistVulScores(Vulnerability vulnerability, OssIndexVulnerability ossIndexVulnerability) {
        List<VulScore> vulScores = new ArrayList<>();

        Map<Pair<String, Double>, VulScore> existVulScores = Optional.ofNullable(vulnerability.getVulScores())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getScoringSystem(), it.getScore()), Function.identity()));

        VulScoringSystem vulScoringSystem;
        if (ossIndexVulnerability.getCvssVector().contains("CVSS:3")) {
            vulScoringSystem = VulScoringSystem.CVSS3;

        } else {
            vulScoringSystem = VulScoringSystem.CVSS2;
        }
        VulScore vulScoreCvss3 = existVulScores.getOrDefault(
                Pair.of(vulScoringSystem.name(), ossIndexVulnerability.getCvssScore()), new VulScore());
        vulScoreCvss3.setScoringSystem(vulScoringSystem.name());
        vulScoreCvss3.setScore(ossIndexVulnerability.getCvssScore());
        vulScoreCvss3.setVector(ossIndexVulnerability.getCvssVector());
        vulScoreCvss3.setVulnerability(vulnerability);
        vulScores.add(vulScoreCvss3);

        return vulScores;
    }

}
