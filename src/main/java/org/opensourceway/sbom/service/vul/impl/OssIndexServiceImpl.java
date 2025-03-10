package org.opensourceway.sbom.service.vul.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.opensourceway.sbom.api.vul.OssIndexClient;
import org.opensourceway.sbom.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.VulnerabilityRepository;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.VulReference;
import org.opensourceway.sbom.model.entity.VulScore;
import org.opensourceway.sbom.model.entity.Vulnerability;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.enums.VulRefSource;
import org.opensourceway.sbom.model.enums.VulScoringSystem;
import org.opensourceway.sbom.model.enums.VulSource;
import org.opensourceway.sbom.model.enums.VulStatus;
import org.opensourceway.sbom.model.pojo.request.vul.ossindex.ComponentReportRequestBody;
import org.opensourceway.sbom.model.pojo.response.vul.ossindex.ComponentReportElement;
import org.opensourceway.sbom.model.pojo.response.vul.ossindex.OssIndexVulnerability;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.service.vul.AbstractVulService;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    private static List<String> convertPackageType(ExternalPurlRef ref) {
        if (ReferenceCategory.PACKAGE_MANAGER.equals(ReferenceCategory.findReferenceCategory(ref.getCategory()))
                && TYPE_CONVERT_MAP.containsKey(ref.getPurl().getType())) {
            return TYPE_CONVERT_MAP.get(ref.getPurl().getType()).stream()
                    .filter(type -> !(StringUtils.equalsIgnoreCase(type, "maven") && StringUtils.isEmpty(ref.getPurl().getNamespace())))
                    .map(type -> PurlUtil.convertPackageType(ref.getPurl(), type))
                    .toList();
        }
        return List.of(PurlUtil.canonicalizePurl(ref.getPurl()));
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
                    if (externalVulRefExistence.contains(Pair.of(vulnerability.getId(), PurlUtil.canonicalizePurl(ref.getPurl())))) {
                        return;
                    }
                    Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional.ofNullable(ref.getPkg().getExternalVulRefs())
                            .orElse(new ArrayList<>())
                            .stream()
                            .collect(Collectors.toMap(it ->
                                            Pair.of(it.getVulnerability().getId(), PurlUtil.canonicalizePurl(it.getPurl())),
                                    Function.identity()));
                    ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(
                            vulnerability.getId(), PurlUtil.canonicalizePurl(ref.getPurl())), new ExternalVulRef());
                    externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
                    externalVulRef.setType(ReferenceType.CVE.getType());
                    externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.NOT_FIXED.name()));
                    externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(PurlUtil.canonicalizePurl(ref.getPurl())));
                    externalVulRef.setVulnerability(vulnerability);
                    externalVulRef.setPkg(ref.getPkg());
                    externalVulRefRepository.saveAndFlush(externalVulRef);
                    externalVulRefExistence.add(Pair.of(vulnerability.getId(), PurlUtil.canonicalizePurl(ref.getPurl())));
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
        VulScore vulScore = existVulScores.getOrDefault(
                Pair.of(vulScoringSystem.name(), ossIndexVulnerability.getCvssScore()), new VulScore());
        vulScore.setScoringSystem(vulScoringSystem.name());
        vulScore.setScore(ossIndexVulnerability.getCvssScore());
        vulScore.setVector(ossIndexVulnerability.getCvssVector());
        vulScore.setVulnerability(vulnerability);
        vulScore.setSeverity(CvssSeverity.calculateCvssSeverity(vulScoringSystem, ossIndexVulnerability.getCvssScore()).name());
        vulScores.add(vulScore);

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
    public Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk,
                                                                        String productType) {
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
                String requestBody = null;
                try {
                    requestBody = Mapper.jsonMapper.writeValueAsString(new ComponentReportRequestBody(requestPurlsChunk));
                } catch (JsonProcessingException ex) {
                    logger.error("convert ComponentReportRequestBody failed", ex);
                }
                logger.error("failed to extract vulnerabilities from OssIndex for sbom {}, request body:{}", sbomId, requestBody, e);
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
                    PurlUtil.canonicalizePurl(purlRef.getPurl())))) {
                continue;
            }

            Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional
                    .ofNullable(purlOwnerPackage.getExternalVulRefs())
                    .orElse(new ArrayList<>())
                    .stream()
                    .collect(Collectors.toMap(it ->
                                    Pair.of(it.getVulnerability().getId(), PurlUtil.canonicalizePurl(it.getPurl())),
                            Function.identity()));
            ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(
                    vulnerability.getId(), PurlUtil.canonicalizePurl(purlRef.getPurl())), new ExternalVulRef());
            externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
            externalVulRef.setType(ReferenceType.CVE.getType());
            externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.NOT_FIXED.name()));
            externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(PurlUtil.canonicalizePurl(purlRef.getPurl())));
            externalVulRef.setVulnerability(vulnerability);
            externalVulRef.setPkg(purlOwnerPackage);
            externalVulRefRepository.saveAndFlush(externalVulRef);
            externalVulRefExistence.add(Triple.of(purlOwnerPackage.getId(), vulnerability.getId(),
                    PurlUtil.canonicalizePurl(purlRef.getPurl())));
        }
    }
}