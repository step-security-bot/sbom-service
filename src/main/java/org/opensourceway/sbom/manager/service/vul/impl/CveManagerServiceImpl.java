package org.opensourceway.sbom.manager.service.vul.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.clients.cvemanager.CveManagerClient;
import org.opensourceway.sbom.clients.cvemanager.model.ComponentReport;
import org.opensourceway.sbom.clients.cvemanager.model.CveManagerVulnerability;
import org.opensourceway.sbom.clients.cvemanager.model.IssueStatus;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.VulnerabilityRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.Package;
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
import org.opensourceway.sbom.manager.utils.CvssSeverity;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@Qualifier("cveManagerServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class CveManagerServiceImpl extends AbstractVulService {

    private static final Logger logger = LoggerFactory.getLogger(CveManagerServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 128;

    @Autowired
    private CveManagerClient cveManagerClient;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private PackageRepository packageRepository;

    private Vulnerability persistVulnerability(CveManagerVulnerability cveManagerVulnerability) {
        Vulnerability vulnerability = vulnerabilityRepository.findByVulIdAndSource(
                cveManagerVulnerability.getCveNum(), VulSource.CVE_MANAGER.name()).orElse(new Vulnerability());
        vulnerability.setVulId(cveManagerVulnerability.getCveNum());
        vulnerability.setType(ReferenceType.CVE.getType());
        vulnerability.setSource(VulSource.CVE_MANAGER.name());
        List<VulReference> vulReferences = persistVulReferences(vulnerability, cveManagerVulnerability);
        vulnerability.setVulReferences(vulReferences);
        List<VulScore> vulScores = persistVulScores(vulnerability, cveManagerVulnerability);
        vulnerability.setVulScores(vulScores);
        return vulnerability;
    }

    private List<VulReference> persistVulReferences(Vulnerability vulnerability, CveManagerVulnerability cveManagerVulnerability) {
        List<VulReference> vulReferences = new ArrayList<>();

        Map<Pair<String, String>, VulReference> existVulReferences = Optional.ofNullable(vulnerability.getVulReferences())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getSource(), it.getUrl()), Function.identity()));

        VulReference vulReference = existVulReferences.getOrDefault(
                Pair.of(VulRefSource.NVD.name(), cveManagerVulnerability.getCveUrl()), new VulReference());
        vulReference.setSource(VulRefSource.NVD.name());
        vulReference.setUrl(cveManagerVulnerability.getCveUrl());
        vulReference.setVulnerability(vulnerability);
        vulReferences.add(vulReference);

        return vulReferences;
    }

    private List<VulScore> persistVulScores(Vulnerability vulnerability, CveManagerVulnerability cveManagerVulnerability) {
        List<VulScore> vulScores = new ArrayList<>();

        Map<Pair<String, Double>, VulScore> existVulScores = Optional.ofNullable(vulnerability.getVulScores())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getScoringSystem(), it.getScore()), Function.identity()));

        Double score;
        String vector;
        if (!StringUtils.isEmpty(cveManagerVulnerability.getNvdVector())) {
            score = cveManagerVulnerability.getNvdScore();
            vector = cveManagerVulnerability.getNvdVector();
        } else if (!StringUtils.isEmpty(cveManagerVulnerability.getOpenEulerVector())) {
            score = cveManagerVulnerability.getOpenEulerScore();
            vector = cveManagerVulnerability.getOpenEulerVector();
        } else {
            return vulScores;
        }

        VulScoringSystem vulScoringSystem = VulScoringSystem.findVulScoringSystemByName(cveManagerVulnerability.getScoringSystem());
        VulScore vulScore = existVulScores.getOrDefault(Pair.of(vulScoringSystem.name(), score), new VulScore());
        vulScore.setScoringSystem(vulScoringSystem.name());
        vulScore.setScore(score);
        vulScore.setVector(vector);
        vulScore.setVulnerability(vulnerability);
        vulScore.setSeverity(CvssSeverity.calculateCvssSeverity(vulScoringSystem, score).name());
        vulScores.add(vulScore);

        return vulScores;
    }

    @Override
    public Integer getBulkRequestSize() {
        return BULK_REQUEST_SIZE;
    }

    @Override
    public boolean needRequest() {
        return cveManagerClient.needRequest();
    }

    @Override
    public Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk,
                                                                        String productType) {
        logger.info("Start to extract vulnerability from cve-manager for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, Object>> resultSet = new HashSet<>();

        List<String> requestPurls = externalPurlChunk.stream()
                .map(ref -> PurlUtil.canonicalizePurl(ref.getPurl()))
                .collect(Collectors.toSet())
                .stream().toList();

        ListUtils.partition(requestPurls, getBulkRequestSize()).forEach(requestPurlsChunk -> {
            try {
                ComponentReport response = cveManagerClient.getComponentReport(requestPurlsChunk).block();
                if (Objects.isNull(response) || CollectionUtils.isEmpty(response.getData())) {
                    return;
                }

                externalPurlChunk.forEach(purlRef -> response.getData()
                        .stream()
                        .filter(vul -> StringUtils.equals(PurlUtil.canonicalizePurl(purlRef.getPurl()), vul.getPurl()))
                        .filter(vul -> VulStatus.activeVulStatus.stream().map(VulStatus::getStatus).toList().contains(vul.getStatus()))
                        .filter(vul -> !Objects.equals(IssueStatus.DELETED.getStatus(), vul.getIssueStatus()))
                        .filter(vul -> filterProductType(productType, vul.getOwner()))
                        .filter(vul -> Pattern.compile("^CVE-\\d+-\\d+$").matcher(vul.getCveNum()).matches())
                        .forEach(vul -> resultSet.add(Pair.of(purlRef, vul))));
            } catch (Exception e) {
                logger.error("failed to extract vulnerabilities from cve-manager for sbom {}", sbomId);
                reportVulFetchFailure(sbomId);
                throw e;
            }
        });

        logger.info("End to extract vulnerability from cve-manager for sbom {}", sbomId);
        return resultSet;
    }

    private boolean filterProductType(String productType, String vulOwner) {
        if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENEULER_NAME) &&
                StringUtils.equalsIgnoreCase(vulOwner, SbomConstants.SOURCE_OPENEULER_NAME)) {
            return true;
        }
        return StringUtils.equalsIgnoreCase(productType, vulOwner);
    }

    @Override
    public void persistExternalVulRefChunk(Set<Pair<ExternalPurlRef, Object>> externalVulRefSet) {
        for (Pair<ExternalPurlRef, Object> externalVulRefPair : externalVulRefSet) {
            ExternalPurlRef purlRef = externalVulRefPair.getLeft();
            Package purlOwnerPackage = packageRepository.findById(purlRef.getPkg().getId())
                    .orElseThrow(() -> new RuntimeException("package id: %s not found".formatted(purlRef.getPkg().getId())));

            CveManagerVulnerability vul = (CveManagerVulnerability) externalVulRefPair.getRight();

            Vulnerability vulnerability = vulnerabilityRepository.saveAndFlush(persistVulnerability(vul));
            Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional.ofNullable(purlOwnerPackage.getExternalVulRefs())
                    .orElse(new ArrayList<>())
                    .stream()
                    .collect(Collectors.toMap(it ->
                                    Pair.of(it.getVulnerability().getId(), PurlUtil.canonicalizePurl(it.getPurl())),
                            Function.identity()));
            ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(vulnerability.getId(), vul.getPurl()), new ExternalVulRef());
            externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
            externalVulRef.setType(ReferenceType.CVE.getType());
            externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.findVulStatusByStatus(vul.getStatus())));
            externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(vul.getPurl()));
            externalVulRef.setVulnerability(vulnerability);
            externalVulRef.setPkg(purlOwnerPackage);
            externalVulRefRepository.saveAndFlush(externalVulRef);
        }
    }

}
