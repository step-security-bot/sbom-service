package org.opensourceway.sbom.service.checksum.impl;

import org.opensourceway.sbom.api.checksum.ChecksumService;
import org.opensourceway.sbom.api.checksum.SonatypeClient;
import org.opensourceway.sbom.cache.ChecksumSkipMapCache;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.dao.PackageMetaRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.PackageMeta;
import org.opensourceway.sbom.model.pojo.response.checksum.maven.Docs;
import org.opensourceway.sbom.model.pojo.response.checksum.maven.GAVInfo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;

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

    @Autowired
    private ChecksumSkipMapCache checksumSkipMapCache;

    @Autowired
    private PackageMetaRepository packageMetaRepository;

    private boolean checksumSkip(Docs docs) {
        List<String> groupToSkip = checksumSkipMapCache.getChecksumSkipMap(CacheConstants.CHECKSUM_SKIP_MAP_CACHE_KEY_PATTERN).get(SbomConstants.CHECKSUM_SKIP_GROUP);
        if (groupToSkip.contains(docs.getGroup())) {
            return true;
        }
        List<String> artifactToSkip = checksumSkipMapCache.getChecksumSkipMap(CacheConstants.CHECKSUM_SKIP_MAP_CACHE_KEY_PATTERN).get(SbomConstants.CHECKSUM_SKIP_ARTIFACT);
        return artifactToSkip.contains(docs.getArtifact());
    }

    @Override
    public boolean needRequest() {
        return sonatypeClient.needRequest();
    }

    @Override
    public List<List<ExternalPurlRef>> extractGAVByChecksumRef(UUID pkgId, String category, String type) {
        List<ExternalPurlRef> externalPurlRefsTOChange = new ArrayList<>();
        List<ExternalPurlRef> externalPurlRefsTORemove = new ArrayList<>();
        Set<PackageUrlVo> vos = new HashSet<>();
        List<ExternalPurlRef> ExternalPurlRefList = externalPurlRefRepository.queryPackageRef(pkgId, category, type);
        ExternalPurlRefList.forEach(ref -> {
            PackageUrlVo vo = getPurlByChecksum(ref);
            if (ObjectUtils.isEmpty(vo) || vos.contains(vo)) {
                logger.debug("GAV of checksum {} already exists", ref.getPurl().getName());
                externalPurlRefsTORemove.add(ref);
            } else {
                ref.setPurl(vo);
                ref.setType(ReferenceType.PURL.getType());
                externalPurlRefsTOChange.add(ref);
                vos.add(vo);
            }
        });
        List<List<ExternalPurlRef>> resultList = new ArrayList<>();
        resultList.add(externalPurlRefsTOChange);
        resultList.add(externalPurlRefsTORemove);
        return resultList;

    }

    private PackageUrlVo getPurlByChecksum(ExternalPurlRef ref) {
        PackageMeta meta = packageMetaRepository.findById(ref.getPurl().getName()).orElse(null);
        if (!ObjectUtils.isEmpty(meta)) {
            return meta.getPurl();
        }

        GAVInfo gavInfo;
        try {
            gavInfo = sonatypeClient.getGAVByChecksum(ref.getPurl().getName());
        } catch (Exception e) {
            logger.error("failed to GAV info for {} from API", ref);
            throw new RuntimeException(e);
        }

        PackageUrlVo vo;
        Docs checksumDocs = gavInfo.getResponse().getDocs().stream().filter(doc -> !checksumSkip(doc)).findFirst().orElse(null);
        if (ObjectUtils.isEmpty(checksumDocs)) {
            logger.debug("can not get GAV info for checksum {}", ref.getPurl().getName());
            vo = null;
        } else {
            vo = new PackageUrlVo();
            vo.setSchema(ref.getPurl().getSchema());
            vo.setType(ref.getPurl().getType());
            vo.setNamespace(checksumDocs.getGroup());
            vo.setName(checksumDocs.getArtifact());
            vo.setVersion(checksumDocs.getVersion());
            vo.setSubpath(ref.getPurl().getSubpath());
            vo.setQualifiers(ref.getPurl().getQualifiers());
        }

        PackageMeta packageMeta = new PackageMeta();
        packageMeta.setChecksum(ref.getPurl().getName());
        packageMeta.setChecksumType(ref.getPurl().getNamespace());
        packageMeta.setPurl(vo);
        packageMeta.setExtendedAttr(Map.of("doc_count", gavInfo.getResponse().getNumFound()));

        synchronized (this) {
            try {
                meta = packageMetaRepository.findById(ref.getPurl().getName()).orElse(null);
                if (!ObjectUtils.isEmpty(meta)) {
                    return meta.getPurl();
                }
                Executors.newFixedThreadPool(1).submit(() -> packageMetaRepository.saveAndFlush(packageMeta)).get();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        return vo;
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