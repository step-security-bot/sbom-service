package org.opensourceway.sbom.manager.service.checksum.impl;

import org.opensourceway.sbom.clients.sonatype.SonatypeClient;
import org.opensourceway.sbom.clients.sonatype.vo.Docs;
import org.opensourceway.sbom.clients.sonatype.vo.GAVInfo;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.service.checksum.ChecksumService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@Qualifier("checksumServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class ChecksumServiceImpl implements ChecksumService {

    private static final Logger logger = LoggerFactory.getLogger(ChecksumServiceImpl.class);

    @Autowired
    @Qualifier("sonatypeClientImpl")
    private SonatypeClient sonatypeClient;

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Override
    public boolean needRequest() {
        return sonatypeClient.needRequest();
    }

    @Override
    public List<List<ExternalPurlRef>> extractGAVByChecksumRef(UUID pkgId, String category, String type) {
        List<ExternalPurlRef> externalPurlRefsTOChange = new ArrayList<>();
        List<ExternalPurlRef> externalPurlRefsTORemove = new ArrayList<>();
        Set<String> gavId = new HashSet<>();
        List<ExternalPurlRef> ExternalPurlRefList = externalPurlRefRepository.queryPackageRef(pkgId, category, type);
        ExternalPurlRefList.forEach(externalPurl -> {
            GAVInfo gavInfo;
            try {
                gavInfo = sonatypeClient.getGAVByChecksum(externalPurl.getPurl().getName());
            } catch (Exception e) {
                logger.error("failed to GAV info for {} from API", externalPurl);
                throw new RuntimeException(e);
            }
            if (gavInfo.getResponse().getNumFound() != 0) {
                Docs checksumDocs;
                if (SbomConstants.CHECKSUM_SKIP_GROUP.equals(gavInfo.getResponse().getDocs().get(0).getGroup()) && gavInfo.getResponse().getNumFound() > 1) {
                    checksumDocs = gavInfo.getResponse().getDocs().get(1);
                } else {
                    checksumDocs = gavInfo.getResponse().getDocs().get(0);
                }
                if (gavId.contains(checksumDocs.getId())) {
                    logger.debug("GAV of checksum {} has already existed", externalPurl.getPurl().getName());
                    externalPurlRefsTORemove.add(externalPurl);
                } else {
                    String group = checksumDocs.getGroup();
                    String artifact = checksumDocs.getArtifact();
                    String version = checksumDocs.getVersion();
                    externalPurl.getPurl().setNamespace(group);
                    externalPurl.getPurl().setName(artifact);
                    externalPurl.getPurl().setVersion(version);
                    externalPurl.setType("purl");
                    externalPurlRefsTOChange.add(externalPurl);
                    gavId.add(checksumDocs.getId());
                    logger.debug("get GAV from checksum for {}", externalPurl.getPurl().getName());
                }
            } else {
                logger.debug("can not get GAV info for checksum {}", externalPurl.getPurl().getName());
                externalPurlRefsTORemove.add(externalPurl);
            }
        });
        List<List<ExternalPurlRef>> resultList = new ArrayList<>();
        resultList.add(externalPurlRefsTOChange);
        resultList.add(externalPurlRefsTORemove);
        return resultList;

    }


    @Override
    public void persistExternalGAVRef(List<List<ExternalPurlRef>> externalPurlRefList) {
        List<ExternalPurlRef> externalPurlRefsTOChange = externalPurlRefList.get(0);
        List<ExternalPurlRef> externalPurlRefsTORemove = externalPurlRefList.get(1);
        // TODO delete can not real remove date
//        for (ExternalPurlRef externalPurlRef : externalPurlRefsTOChange) {
//            externalPurlRefRepository.save(externalPurlRef);
//        }
        externalPurlRefRepository.saveAll(externalPurlRefsTOChange);

//        for (ExternalPurlRef externalPurlRef : externalPurlRefsTORemove) {
//            externalPurlRefRepository.delete(externalPurlRef);
//        }
        externalPurlRefRepository.deleteAllInBatch(externalPurlRefsTORemove);
    }

}