package org.opensourceway.sbom.openeuler.obs;

import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.clients.vcs.gitee.model.GiteeBranchInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenEulerRepoCache {

    private static final Logger logger = LoggerFactory.getLogger(OpenEulerRepoCache.class);

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties openEulerRepoCacheProperties() {
        // TODO 后续调小缓存最大值和过期时限
        return CacheProperties.builder()
                .cacheName(CacheConstants.OPENEULER_REPO_BRANCHES_CACHE_NAME)
                .maximumCacheSize(5500L)
                .expireAfterAccess(3 * 60L * 60L)// 3h
                .cacheNullValue(true)
                .build();
    }

    @Cacheable(value = {CacheConstants.OPENEULER_REPO_BRANCHES_CACHE_NAME}, key = CacheConstants.OPENEULER_REPO_BRANCHES_CACHE_KEY_PATTERN)
    public List<GiteeBranchInfo.BranchInfo> getRepoBranches(String org, String repo) {
        return giteeApi.getRepoBranches(org, repo);
    }

}