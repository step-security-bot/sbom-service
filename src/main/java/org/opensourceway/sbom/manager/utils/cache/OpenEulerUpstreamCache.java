package org.opensourceway.sbom.manager.utils.cache;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.clients.vcs.gitee.GiteeApi;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.opensourceway.sbom.openeuler.obs.SbomRepoConstants;
import org.opensourceway.sbom.utils.OpenEulerAdvisorParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.yaml.snakeyaml.scanner.ScannerException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Configuration
public class OpenEulerUpstreamCache {

    private static final Logger logger = LoggerFactory.getLogger(OpenEulerUpstreamCache.class);

    @Autowired
    private GiteeApi giteeApi;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private OpenEulerAdvisorParser advisorParser;

    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties openEulerUpstreamCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.OPENEULER_UPSTREAM_URLS_CACHE_NAME)
                .maximumCacheSize(1000L)
                .expireAfterAccess(60L * 60L)// 1h
                .cacheNullValue(true)
                .build();
    }

    @Cacheable(value = {CacheConstants.OPENEULER_UPSTREAM_URLS_CACHE_NAME}, key = CacheConstants.OPENEULER_UPSTREAM_CACHE_KEY_PATTERN)
    public List<String> getUpstreamUrls(String repo, String branch) {
        List<String> upstreamUrls = new ArrayList<>();

        Optional<RepoMeta> repoMetaOptional = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(SbomConstants.PRODUCT_OPENEULER_NAME, repo, branch);
        if (repoMetaOptional.isEmpty()) {
            return upstreamUrls;
        }
        RepoMeta repoMeta = repoMetaOptional.get();
        Map<String, Object> extendedAttrs = repoMeta.getExtendedAttr() == null ? new HashMap<>() : repoMeta.getExtendedAttr();
        if (extendedAttrs.containsKey(SbomRepoConstants.UPSTREAM_ATTR_KEY)) {
            return (List<String>) extendedAttrs.get(SbomRepoConstants.UPSTREAM_ATTR_KEY);
        }

        if (ArrayUtils.isEmpty(repoMeta.getUpstreamDownloadUrls())) {
            return upstreamUrls;
        }

        boolean isUpdateRepoMeta = true;
        for (String upstreamDownloadUrl : repoMeta.getUpstreamDownloadUrls()) {
            try {
                String advisorContent = giteeApi.getFileContext(upstreamDownloadUrl);
                String upstreamLocation = advisorParser.parseUpstreamLocation(advisorContent, upstreamDownloadUrl);
                if (StringUtils.isEmpty(upstreamLocation)) {
                    continue;
                }
                upstreamUrls.add(upstreamLocation);
            } catch (ScannerException e) {
                logger.error("openEuler upstream yaml parse failed, skip it, upstream:{}, error info:{}", upstreamDownloadUrl, e.getMessage());
            } catch (Exception e) {
                logger.error("openEuler upstream fetch failed, upstream:{}", upstreamDownloadUrl, e);
                isUpdateRepoMeta = false;
            }
        }

        if (isUpdateRepoMeta) {
            extendedAttrs.put(SbomRepoConstants.UPSTREAM_ATTR_KEY, upstreamUrls);
            repoMeta.setExtendedAttr(extendedAttrs);
            repoMetaRepository.save(repoMeta);
        }
        return upstreamUrls;
    }

}