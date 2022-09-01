package org.openeuler.sbom.manager.service.vul.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.openeuler.sbom.clients.cvemanager.CveManagerClient;
import org.openeuler.sbom.clients.cvemanager.model.ComponentReport;
import org.openeuler.sbom.clients.cvemanager.model.CveManagerVulnerability;
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
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
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

    @Override
    public void persistExternalVulRefForSbom(Sbom sbom, Boolean blocking) {
        logger.info("Start to persistExternalVulRefForSbom from cve-manager for sbom {}", sbom.getId());
        if (!cveManagerClient.needRequest()) {
            logger.warn("cveManagerClient does not request");
            return;
        }

        List<ExternalPurlRef> externalPurlRefs = sbom.getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .toList();

        List<List<ExternalPurlRef>> chunks = ListUtils.partition(externalPurlRefs, getBulkRequestSize());
        for (int i = 0; i < chunks.size(); i++) {
            logger.info("fetch vulnerabilities from cve-manager for purl chunk {}, total {}", i + 1, chunks.size());
            List<ExternalPurlRef> chunk = chunks.get(i);
            List<String> purls = chunk.stream()
                    .map(ref -> PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize())
                    .collect(Collectors.toSet())
                    .stream().toList();
            try {
                Mono<ComponentReport> mono = cveManagerClient.getComponentReport(purls);
                if (blocking) {
                    persistExternalVulRef(mono.block(), chunk);
                } else {
                    mono.subscribe(report -> persistExternalVulRef(report, chunk));
                }
            } catch (Exception e) {
                logger.error("failed to fetch vulnerabilities from cve-manager for sbom {}", sbom.getId());
                reportVulFetchFailure(sbom.getId());
                throw e;
            }
        }

        logger.info("End to persistExternalVulRefForSbom from cve-manager for sbom {}", sbom.getId());
    }

    private void persistExternalVulRef(ComponentReport report, List<ExternalPurlRef> externalPurlRefs) {
        if (Objects.isNull(report) || CollectionUtils.isEmpty(report.getData())) {
            return;
        }

        externalPurlRefs.forEach(ref -> report.getData()
                .stream()
                .filter(vul -> StringUtils.equals(PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize(), vul.getPurl()))
                .forEach(vul -> {
                    Vulnerability vulnerability = vulnerabilityRepository.saveAndFlush(persistVulnerability(vul));
                    Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional.ofNullable(ref.getPkg().getExternalVulRefs())
                            .orElse(new ArrayList<>())
                            .stream()
                            .collect(Collectors.toMap(it ->
                                            Pair.of(it.getVulnerability().getId(), PurlUtil.PackageUrlVoToPackageURL(it.getPurl()).canonicalize()),
                                    Function.identity()));
                    ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(vulnerability.getId(), vul.getPurl()), new ExternalVulRef());
                    externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
                    externalVulRef.setType(ReferenceType.CVE.getType());
                    externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.AFFECTED.name()));
                    externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(vul.getPurl()));
                    externalVulRef.setVulnerability(vulnerability);
                    externalVulRef.setPkg(ref.getPkg());
                    externalVulRefRepository.saveAndFlush(externalVulRef);
                }));
    }

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

        VulScore vulScoreCvss2 = existVulScores.getOrDefault(
                Pair.of(VulScoringSystem.CVSS2.name(), cveManagerVulnerability.getCvss2Score()), new VulScore());
        vulScoreCvss2.setScoringSystem(VulScoringSystem.CVSS2.name());
        vulScoreCvss2.setScore(cveManagerVulnerability.getCvss2Score());
        vulScoreCvss2.setVector(cveManagerVulnerability.getCvss2Vector());
        vulScoreCvss2.setVulnerability(vulnerability);
        vulScores.add(vulScoreCvss2);

        VulScore vulScoreCvss3 = existVulScores.getOrDefault(
                Pair.of(VulScoringSystem.CVSS3.name(), cveManagerVulnerability.getCvss3Score()), new VulScore());
        vulScoreCvss3.setScoringSystem(VulScoringSystem.CVSS3.name());
        vulScoreCvss3.setScore(cveManagerVulnerability.getCvss3Score());
        vulScoreCvss3.setVector(cveManagerVulnerability.getCvss3Vector());
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
        return cveManagerClient.needRequest();
    }

    @Override
    public Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk) {
        logger.info("Start to extract vulnerability from cve-manager for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, Object>> resultSet = new HashSet<>();

        List<String> requestPurls = externalPurlChunk.stream()
                .map(ref -> PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize())
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
                        .filter(vul -> StringUtils.equals(PurlUtil.PackageUrlVoToPackageURL(purlRef.getPurl()).canonicalize(), vul.getPurl()))
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

    @Override
    public void persistExternalVulRefChunk(Set<Pair<ExternalPurlRef, Object>> externalVulRefSet) {
        for (Pair<ExternalPurlRef, Object> externalVulRefPair : externalVulRefSet) {
            ExternalPurlRef purlRef = externalVulRefPair.getLeft();
            CveManagerVulnerability vul = (CveManagerVulnerability) externalVulRefPair.getRight();

            Vulnerability vulnerability = vulnerabilityRepository.saveAndFlush(persistVulnerability(vul));
            Map<Pair<UUID, String>, ExternalVulRef> existExternalVulRefs = Optional.ofNullable(purlRef.getPkg().getExternalVulRefs())
                    .orElse(new ArrayList<>())
                    .stream()
                    .collect(Collectors.toMap(it ->
                                    Pair.of(it.getVulnerability().getId(), PurlUtil.PackageUrlVoToPackageURL(it.getPurl()).canonicalize()),
                            Function.identity()));
            ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(vulnerability.getId(), vul.getPurl()), new ExternalVulRef());
            externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
            externalVulRef.setType(ReferenceType.CVE.getType());
            externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.AFFECTED.name()));
            externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(vul.getPurl()));
            externalVulRef.setVulnerability(vulnerability);
            externalVulRef.setPkg(purlRef.getPkg());
            externalVulRefRepository.saveAndFlush(externalVulRef);
        }
    }

}
