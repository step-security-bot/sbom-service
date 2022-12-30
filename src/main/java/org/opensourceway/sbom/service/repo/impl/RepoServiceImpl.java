package org.opensourceway.sbom.service.repo.impl;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.opensourceway.sbom.api.repo.RepoMetaParser;
import org.opensourceway.sbom.api.repo.RepoService;
import org.opensourceway.sbom.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.dao.FileRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.response.sbom.UpstreamAndPatchInfoResponse;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional(rollbackFor = Exception.class)
public class RepoServiceImpl implements RepoService {

    private static final Logger logger = LoggerFactory.getLogger(RepoServiceImpl.class);

    @Autowired
    private RepoMetaParser repoMetaParser;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private FileRepository fileRepository;

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Override
    public Set<RepoInfoVo> fetchOpenEulerRepoMeta() throws IOException {
        Set<RepoInfoVo> repoInfoSet = repoMetaParser.fetchObsMetaSourceCode();

        Iterator<RepoInfoVo> repoInfoIt = repoInfoSet.iterator();
        int counter = 0;

        while (repoInfoIt.hasNext()) {
            RepoInfoVo repoInfo = repoInfoIt.next();
            if (counter++ % 20 == 0) {
                logger.info("fetchOpenEulerRepoMeta run loops:{}, current repo name:{} ,branch:{}", counter, repoInfo.getRepoName(), repoInfo.getBranch());
            }

            RepoMeta repoMeta = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(
                    SbomConstants.PRODUCT_OPENEULER_NAME, repoInfo.getRepoName(), repoInfo.getBranch()).orElse(new RepoMeta());
            String oldLastCommitId = (repoMeta.getExtendedAttr() == null || !repoMeta.getExtendedAttr().containsKey(SbomRepoConstants.LAST_COMMIT_ID_KEY)) ?
                    null : String.valueOf(repoMeta.getExtendedAttr().get(SbomRepoConstants.LAST_COMMIT_ID_KEY));
            Pair<Boolean, String> repoChangeInfo = repoMetaParser.isRepoChanged(repoInfo, oldLastCommitId);
            if (BooleanUtils.isFalse(repoChangeInfo.getFirst())) {
                repoInfoIt.remove();
                continue;
            }

            logger.info("repo name:{}, repo branch:{} has changed, fetch repo info again",
                    repoInfo.getRepoName(),
                    repoInfo.getBranch());
            repoInfo.setId(repoMeta.getId());
            repoInfo.setLastCommitId(repoChangeInfo.getSecond());
            repoMetaParser.fetchRepoBuildFileInfo(repoInfo);
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        logger.info("save new openEuler repo meta set size:{}", repoInfoSet.size());
        repoMetaRepository.saveAll(repoInfoSet.stream()
                .map(temp -> RepoMeta.fromRepoInfoVo(SbomConstants.PRODUCT_OPENEULER_NAME, temp)).toList());
        return repoInfoSet;
    }

    @Override
    public UpstreamAndPatchInfoResponse queryUpstreamAndPatchInfo(String packageId) {
        UpstreamAndPatchInfoResponse response = new UpstreamAndPatchInfoResponse();

        Optional<Package> packageOptional = packageRepository.findById(UUID.fromString(packageId));
        if (packageOptional.isEmpty()) {
            return response;
        }

        Package pkg = packageOptional.get();
        List<ExternalPurlRef> upstreamList = externalPurlRefRepository.queryPackageRef(pkg.getId(), ReferenceCategory.SOURCE_MANAGER.name(), ReferenceType.URL.getType());
        List<File> patchList = fileRepository.findPatchesInfo(pkg.getSbom().getId(), pkg.getSpdxId());

        if (CollectionUtils.isNotEmpty(upstreamList)) {
            List<Map<String, String>> upstreamResult = new ArrayList<>();
            upstreamList.forEach(upstream -> upstreamResult.add(Map.of("url", upstream.getPurl().getName())));
            response.setUpstreamList(upstreamResult);
        }
        if (CollectionUtils.isNotEmpty(patchList)) {
            List<Map<String, String>> patchResult = new ArrayList<>();
            patchList.forEach(patch -> patchResult.add(Map.of("url", patch.getFileName())));
            response.setPatchList(patchResult);
        }
        return response;
    }

}
