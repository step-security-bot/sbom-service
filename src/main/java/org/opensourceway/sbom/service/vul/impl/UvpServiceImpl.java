package org.opensourceway.sbom.service.vul.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.api.vul.UvpClient;
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
import org.opensourceway.sbom.model.enums.VulScoringSystem;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.Reference;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.Severity;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.UvpVulnerability;
import org.opensourceway.sbom.model.pojo.response.vul.uvp.UvpVulnerabilityReport;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.service.vul.AbstractVulService;
import org.opensourceway.sbom.utils.CvssUtil;
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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Qualifier("uvpServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class UvpServiceImpl extends AbstractVulService {

    private static final Logger logger = LoggerFactory.getLogger(UvpServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 128;

    @Autowired
    private UvpClient uvpClient;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Override
    public Integer getBulkRequestSize() {
        return BULK_REQUEST_SIZE;
    }

    @Override
    public boolean needRequest() {
        return uvpClient.needRequest();
    }

    @Override
    public Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk, String productType) {
        logger.info("Start to extract vulnerability from uvp for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, Object>> resultSet = new HashSet<>();

        List<String> requestPurls = externalPurlChunk.stream()
                .map(ref -> PurlUtil.canonicalizePurl(ref.getPurl()))
                .collect(Collectors.toSet())
                .stream().toList();

        ListUtils.partition(requestPurls, getBulkRequestSize()).forEach(requestPurlsChunk -> {
            try {
                UvpVulnerabilityReport[] response = uvpClient.getComponentReport(requestPurlsChunk).block();
                if (ObjectUtils.isEmpty(response)) {
                    return;
                }

                externalPurlChunk.forEach(purlRef -> Arrays.stream(response)
                        .filter(vul -> StringUtils.equals(PurlUtil.canonicalizePurl(purlRef.getPurl()), vul.getPurl()))
                        .forEach(vul -> resultSet.add(Pair.of(purlRef, vul))));
            } catch (Exception e) {
                logger.error("failed to extract vulnerabilities from uvp for sbom {}", sbomId);
                reportVulFetchFailure(sbomId);
                throw e;
            }
        });

        return resultSet;
    }

    @Override
    public void persistExternalVulRefChunk(Set<Pair<ExternalPurlRef, Object>> externalVulRefSet) {
        for (Pair<ExternalPurlRef, Object> externalVulRefPair : externalVulRefSet) {
            UvpVulnerabilityReport vulReport = (UvpVulnerabilityReport) externalVulRefPair.getRight();
            List<UvpVulnerability> uvpVulnerabilities = vulReport.getUvpVulnerabilities();
            if (ObjectUtils.isEmpty(uvpVulnerabilities)) {
                continue;
            }
            ExternalPurlRef purlRef = externalVulRefPair.getLeft();
            persistExternalVulRef(purlRef, uvpVulnerabilities);
        }
    }

    private void persistExternalVulRef(ExternalPurlRef purlRef, List<UvpVulnerability> uvpVulnerabilities) {
        for (UvpVulnerability vul : uvpVulnerabilities) {
            Package purlOwnerPackage = packageRepository.findById(purlRef.getPkg().getId())
                    .orElseThrow(() -> new RuntimeException("package id: %s not found".formatted(purlRef.getPkg().getId())));

            Vulnerability vulnerability = vulnerabilityRepository.saveAndFlush(persistVulnerability(vul));
            Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional.ofNullable(purlOwnerPackage.getExternalVulRefs())
                    .orElse(new ArrayList<>())
                    .stream()
                    .collect(Collectors.toMap(it ->
                                    Pair.of(it.getVulnerability().getId(), PurlUtil.canonicalizePurl(it.getPurl())),
                            Function.identity()));
            ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(vulnerability.getId(), PurlUtil.canonicalizePurl(purlRef.getPurl())), new ExternalVulRef());
            externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
            externalVulRef.setPurl(purlRef.getPurl());
            externalVulRef.setVulnerability(vulnerability);
            externalVulRef.setPkg(purlOwnerPackage);
            externalVulRefRepository.saveAndFlush(externalVulRef);
        }
    }

    private Vulnerability persistVulnerability(UvpVulnerability uvpVulnerability) {
        Vulnerability vulnerability = vulnerabilityRepository.findByVulId(uvpVulnerability.getId()).orElse(new Vulnerability());
        vulnerability.setVulId(uvpVulnerability.getId());
        List<VulReference> vulReferences = persistVulReferences(vulnerability, uvpVulnerability);
        vulnerability.setAliases(uvpVulnerability.getAliases());
        vulnerability.setVulReferences(vulReferences);
        vulnerability.setDescription(uvpVulnerability.getDetails());
        List<VulScore> vulScores = persistVulScores(vulnerability, uvpVulnerability);
        vulnerability.setVulScores(vulScores);
        return vulnerability;
    }

    private List<VulReference> persistVulReferences(Vulnerability vulnerability, UvpVulnerability uvpVulnerability) {
        List<VulReference> vulReferences = new ArrayList<>();

        Map<Pair<String, String>, VulReference> existVulReferences = Optional.ofNullable(vulnerability.getVulReferences())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getSource(), it.getUrl()), Function.identity()));

        for (Reference reference : uvpVulnerability.getReferences()) {
            VulReference vulReference = existVulReferences.getOrDefault(
                    Pair.of(reference.getType(), reference.getUrl()), new VulReference());
            vulReference.setSource(reference.getType());
            vulReference.setUrl(reference.getUrl());
            vulReference.setVulnerability(vulnerability);
            vulReferences.add(vulReference);

        }
        return vulReferences;
    }

    private List<VulScore> persistVulScores(Vulnerability vulnerability, UvpVulnerability uvpVulnerability) {
        List<VulScore> vulScores = new ArrayList<>();
        if (ObjectUtils.isEmpty(uvpVulnerability.getSeverities())) {
            return vulScores;
        }

        Map<Pair<String, Double>, VulScore> existVulScores = Optional.ofNullable(vulnerability.getVulScores())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getScoringSystem(), it.getScore()), Function.identity()));

        for (Severity severity : uvpVulnerability.getSeverities()) {
            Double score;
            String vector;
            vector = severity.getScore();
            score = CvssUtil.calculateScore(vector);
            VulScoringSystem vulScoringSystem = VulScoringSystem.findVulScoringSystemByName(severity.getType());
            VulScore vulScore = existVulScores.getOrDefault(Pair.of(vulScoringSystem.name(), score), new VulScore());
            vulScore.setScoringSystem(vulScoringSystem.name());
            vulScore.setScore(score);
            vulScore.setVector(vector);
            vulScore.setVulnerability(vulnerability);
            vulScore.setSeverity(CvssSeverity.calculateCvssSeverity(vulScoringSystem, score).name());
            vulScores.add(vulScore);
        }

        return vulScores;
    }
}
