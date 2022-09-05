package org.opensourceway.sbom.manager.service.vul.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.opensourceway.sbom.clients.ossindex.OssIndexClient;
import org.opensourceway.sbom.clients.ossindex.model.ComponentReportElement;
import org.opensourceway.sbom.clients.ossindex.model.OssIndexVulnerability;
import org.opensourceway.sbom.manager.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.VulnerabilityRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.VulRefSource;
import org.opensourceway.sbom.manager.model.VulReference;
import org.opensourceway.sbom.manager.model.VulScore;
import org.opensourceway.sbom.manager.model.VulScoringSystem;
import org.opensourceway.sbom.manager.model.VulSource;
import org.opensourceway.sbom.manager.model.VulStatus;
import org.opensourceway.sbom.manager.model.Vulnerability;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.spdx.ReferenceType;
import org.opensourceway.sbom.manager.service.vul.AbstractVulService;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
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
@Qualifier("ossIndexServiceImpl")
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

    @Autowired
    private PackageRepository packageRepository;

    @Override
    public void persistExternalVulRefForSbom(Sbom sbom, Boolean blocking) {
        logger.info("Start to persistExternalVulRefForSbom from OssIndex for sbom {}", sbom.getId());
        if (!ossIndexClient.needRequest()) {
            logger.warn("ossIndexClient does not request");
            return;
        }

        List<ExternalPurlRef> externalPurlRefs = sbom.getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .toList();

        List<List<ExternalPurlRef>> chunks = ListUtils.partition(externalPurlRefs, getBulkRequestSize());
        for (int i = 0; i < chunks.size(); i++) {
            logger.info("fetch vulnerabilities from OssIndex for purl chunk {}, total {}", i + 1, chunks.size());
            List<ExternalPurlRef> chunk = chunks.get(i);
            Map<ExternalPurlRef, List<String>> refToConvertedPurl = chunk.stream()
                    .collect(Collectors.toMap(Function.identity(), OssIndexServiceImpl::convertPackageType));
            List<String> purls = refToConvertedPurl.values().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toSet())
                    .stream().toList();
            ListUtils.partition(purls, getBulkRequestSize()).forEach(chunkPurl -> {
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
                    .filter(type -> !(StringUtils.equalsIgnoreCase(type, "maven") && StringUtils.isEmpty(ref.getPurl().getNamespace())))
                    .map(type -> PurlUtil.convertPackageType(ref.getPurl(), type))
                    .toList();
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

    @Override
    public Integer getBulkRequestSize() {
        return BULK_REQUEST_SIZE;
    }

    @Override
    public boolean needRequest() {
        return ossIndexClient.needRequest();
    }

    @Override
    public Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk) {
        logger.info("Start to extract vulnerability from OssIndex for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, Object>> resultSet = new HashSet<>();

        Map<ExternalPurlRef, List<String>> purlRefWithMultiTypePurls = externalPurlChunk.stream()
                .collect(Collectors.toMap(Function.identity(), OssIndexServiceImpl::convertPackageType));
        List<String> requestPurls = purlRefWithMultiTypePurls.values().stream()
                .flatMap(List::stream)
                .collect(Collectors.toSet())
                .stream().toList();

        ListUtils.partition(requestPurls, getBulkRequestSize()).forEach(requestPurlsChunk -> {
            try {
                ComponentReportElement[] responses = ossIndexClient.getComponentReport(requestPurlsChunk).block();
                if (Objects.isNull(responses) || responses.length == 0) {
                    return;
                }

                purlRefWithMultiTypePurls.forEach((purlRef, multiTypePurls) -> Arrays.stream(responses)
                        .filter(response -> multiTypePurls.contains(response.getCoordinates()))
                        .map(ComponentReportElement::getVulnerabilities)
                        .flatMap(List::stream)
                        .forEach(responseVul -> {
                            if (StringUtils.isEmpty(responseVul.getCve())) {
                                return;
                            }
                            resultSet.add(Pair.of(purlRef, responseVul));
                        }));
            } catch (Exception e) {
                logger.error("failed to extract vulnerabilities from OssIndex for sbom {}", sbomId);
                reportVulFetchFailure(sbomId);
                throw e;
            }
        });

        logger.info("End to extract vulnerability from OssIndex for sbom {}", sbomId);
        return resultSet;
    }

    @Override
    public void persistExternalVulRefChunk(Set<Pair<ExternalPurlRef, Object>> externalVulRefSet) {
        Set<Triple<UUID, UUID, String>> externalVulRefExistence = new HashSet<>();

        for (Pair<ExternalPurlRef, Object> externalVulRefPair : externalVulRefSet) {
            ExternalPurlRef purlRef = externalVulRefPair.getLeft();
            Package purlOwnerPackage = packageRepository.findById(purlRef.getPkg().getId())
                    .orElseThrow(() -> new RuntimeException("package id: %s not found".formatted(purlRef.getPkg().getId())));

            OssIndexVulnerability vul = (OssIndexVulnerability) externalVulRefPair.getRight();

            Vulnerability vulnerability = vulnerabilityRepository.saveAndFlush(persistVulnerability(vul));
            if (externalVulRefExistence.contains(Triple.of(purlOwnerPackage.getId(), vulnerability.getId(),
                    PurlUtil.PackageUrlVoToPackageURL(purlRef.getPurl()).canonicalize()))) {
                continue;
            }

            Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional
                    .ofNullable(purlOwnerPackage.getExternalVulRefs())
                    .orElse(new ArrayList<>())
                    .stream()
                    .collect(Collectors.toMap(it ->
                                    Pair.of(it.getVulnerability().getId(), PurlUtil.PackageUrlVoToPackageURL(it.getPurl()).canonicalize()),
                            Function.identity()));
            ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(
                    vulnerability.getId(), PurlUtil.PackageUrlVoToPackageURL(purlRef.getPurl()).canonicalize()), new ExternalVulRef());
            externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
            externalVulRef.setType(ReferenceType.CVE.getType());
            externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.AFFECTED.name()));
            externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(PurlUtil.PackageUrlVoToPackageURL(purlRef.getPurl()).canonicalize()));
            externalVulRef.setVulnerability(vulnerability);
            externalVulRef.setPkg(purlOwnerPackage);
            externalVulRefRepository.saveAndFlush(externalVulRef);
            externalVulRefExistence.add(Triple.of(purlOwnerPackage.getId(), vulnerability.getId(),
                    PurlUtil.PackageUrlVoToPackageURL(purlRef.getPurl()).canonicalize()));
        }
    }
}