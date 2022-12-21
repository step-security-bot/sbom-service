package org.opensourceway.sbom.cache;

import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeBranchInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenEulerRepoBranchCache {

    private static final Logger logger = LoggerFactory.getLogger(OpenEulerRepoBranchCache.class);

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties openEulerRepoCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.OPENEULER_REPO_BRANCHES_CACHE_NAME)
                .maximumCacheSize(6000L)
                .expireAfterAccess(2 * 60L * 60L)// 2h
                .cacheNullValue(true)
                .build();
    }

    @Cacheable(value = {CacheConstants.OPENEULER_REPO_BRANCHES_CACHE_NAME}, key = CacheConstants.OPENEULER_REPO_BRANCHES_CACHE_KEY_PATTERN)
    public List<GiteeBranchInfo.BranchInfo> getRepoBranches(String org, String repo) {
        return (List<GiteeBranchInfo.BranchInfo>) giteeApi.getRepoBranches(org, repo);
    }

}