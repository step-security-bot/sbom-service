package org.opensourceway.sbom.manager.service.repo.impl;

import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.opensourceway.sbom.manager.service.repo.RepoService;
import org.opensourceway.sbom.openeuler.obs.RepoMetaParser;
import org.opensourceway.sbom.openeuler.obs.vo.RepoInfoVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.List;
import java.util.Set;

@Service
@Transactional(rollbackFor = Exception.class)
public class RepoServiceImpl implements RepoService {

    private static final Logger logger = LoggerFactory.getLogger(RepoServiceImpl.class);

    @Autowired
    private RepoMetaParser repoMetaParser;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

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
}
