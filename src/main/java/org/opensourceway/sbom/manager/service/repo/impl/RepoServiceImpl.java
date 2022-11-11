package org.opensourceway.sbom.manager.service.repo.impl;

import org.apache.commons.collections4.CollectionUtils;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.manager.dao.FileRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.File;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.spdx.ReferenceType;
import org.opensourceway.sbom.manager.model.vo.response.UpstreamAndPatchInfoResponse;
import org.opensourceway.sbom.manager.service.repo.RepoService;
import org.opensourceway.sbom.openeuler.obs.RepoMetaParser;
import org.opensourceway.sbom.openeuler.obs.vo.RepoInfoVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.ArrayList;
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
        repoMetaParser.fetchRepoBuildFileInfo(repoInfoSet);
        repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfoSet);

        // TODO parse upstream info form yaml
        // repoMetaParser.fetchRepoUpstreamInfo(repoInfoSet);

        logger.info("fetch openEuler repo meta set size:{}", repoInfoSet.size());
        List<RepoMeta> deleteIds = repoMetaRepository.deleteByProductType(SbomConstants.PRODUCT_OPENEULER_NAME);
        logger.info("delete {}'s old data size:{}", SbomConstants.PRODUCT_OPENEULER_NAME, deleteIds == null ? 0 : deleteIds.size());
        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaRepository.save(RepoMeta.fromRepoInfoVo(SbomConstants.PRODUCT_OPENEULER_NAME, repoInfo));
        }
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
