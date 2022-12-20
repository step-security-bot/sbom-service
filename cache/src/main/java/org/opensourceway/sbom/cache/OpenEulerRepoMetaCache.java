package org.opensourceway.sbom.cache;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.api.license.LicenseService;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.vo.license.LicenseInfoVo;
import org.opensourceway.sbom.utils.OpenEulerAdvisorParser;
import org.opensourceway.sbom.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.yaml.snakeyaml.scanner.ScannerException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class OpenEulerRepoMetaCache {

    private static final Logger logger = LoggerFactory.getLogger(OpenEulerRepoMetaCache.class);

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Autowired
    private LicenseClient licenseClient;

    @Autowired
    private LicenseService licenseService;

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
                .cacheName(CacheConstants.OPENEULER_REPO_META_CACHE_NAME)
                .maximumCacheSize(5000L)
                .expireAfterAccess(60L * 60L)// 1h
                .cacheNullValue(true)
                .build();
    }

    @Cacheable(value = {CacheConstants.OPENEULER_REPO_META_CACHE_NAME}, key = CacheConstants.OPENEULER_REPO_META_CACHE_KEY_PATTERN)
    public RepoMeta getRepoMeta(String repo, String branch) {
        Optional<RepoMeta> repoMetaOptional = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(SbomConstants.PRODUCT_OPENEULER_NAME, repo, branch);
        if (repoMetaOptional.isEmpty()) {
            return null;
        }
        RepoMeta repoMeta = repoMetaOptional.get();

        ExecutorService executorService = Executors.newWorkStealingPool();
        List<Callable<Boolean>> fetchTasks = Arrays.asList(
                new FetchUpstreamCallable(repoMeta),
                new FetchLicenseCallable(repoMeta)
        );
        try {
            List<Boolean> tasksResult = executorService.invokeAll(fetchTasks).stream()
                    .map(future -> {
                        try {
                            return future.get();
                        } catch (Exception e) {
                            logger.error("repo:{}, branch:{} get fetch task's result failed", repo, branch, e);
                            return false;
                        }
                    }).toList();

            /*
              聚合所有异步任务的结果，判断是否需要更新repoMeta，不更新的判断逻辑：
              <p>
              1.全为null：无数据更新；
              <p>
              2.有一个False：repoMeta中有脏数据
              */
            boolean isUpdateRepoMeta = !(tasksResult.stream().allMatch(Objects::isNull) || tasksResult.stream().anyMatch(Boolean.FALSE::equals));

            if (isUpdateRepoMeta) {
                repoMetaRepository.save(repoMeta);
            }
        } catch (Exception e) {
            logger.error("", e);
        } finally {
            executorService.shutdown();
        }
        return repoMeta;
    }

    class FetchLicenseCallable implements Callable<Boolean> {

        private final RepoMeta repoMeta;

        FetchLicenseCallable(RepoMeta repoMeta) {
            this.repoMeta = repoMeta;
        }

        @Override
        public Boolean call() {
            Map<String, Object> extendedAttrs = repoMeta.getExtendedAttr() == null ? new ConcurrentHashMap<>() : repoMeta.getExtendedAttr();
            if (extendedAttrs.containsKey(SbomRepoConstants.REPO_LICENSE)) {
                return null;
            }
            LicenseInfoVo licenseInfoVo = new LicenseInfoVo();
            boolean isUpdateRepoMeta = Boolean.TRUE;
            try {
                String purl = PurlUtil.canonicalizePurl(PurlUtil.newPackageURL("gitee", SbomRepoConstants.OPENEULER_REPO_ORG,
                        repoMeta.getRepoName(), repoMeta.getBranch(), null, null));
                licenseInfoVo = licenseService.getLicenseInfoVoFromPurl(List.of(purl)).get(purl);

                if (ObjectUtils.isEmpty(licenseInfoVo)) {
                    return null;
                }
            } catch (Exception e) {
                logger.error("get license for repo {} branch {} from compliance failed, skip it", repoMeta.getRepoName(), repoMeta.getBranch(), e);
                isUpdateRepoMeta = Boolean.FALSE;
            }

            extendedAttrs.put(SbomRepoConstants.REPO_LICENSE, licenseInfoVo.getRepoLicense());
            extendedAttrs.put(SbomRepoConstants.REPO_LICENSE_ILLEGAL, licenseInfoVo.getRepoLicenseIllegal());
            extendedAttrs.put(SbomRepoConstants.REPO_LICENSE_LEGAL, licenseInfoVo.getRepoLicenseLegal());
            extendedAttrs.put(SbomRepoConstants.REPO_COPYRIGHT, licenseInfoVo.getRepoCopyrightLegal());
            repoMeta.setExtendedAttr(extendedAttrs);
            return isUpdateRepoMeta;
        }
    }

    class FetchUpstreamCallable implements Callable<Boolean> {

        private final RepoMeta repoMeta;

        FetchUpstreamCallable(RepoMeta repoMeta) {
            this.repoMeta = repoMeta;
        }

        /**
         * @return null：无数据更新；True：数据可以更新；False：数据异常不可以更新
         */
        @Override
        public Boolean call() {
            Map<String, Object> extendedAttrs = repoMeta.getExtendedAttr() == null ? new ConcurrentHashMap<>() : repoMeta.getExtendedAttr();
            if (extendedAttrs.containsKey(SbomRepoConstants.UPSTREAM_ATTR_KEY)) {
                return null;
            }
            if (ArrayUtils.isEmpty(repoMeta.getUpstreamDownloadUrls())) {
                return null;
            }

            List<String> upstreamUrls = new ArrayList<>();
            boolean isUpdateRepoMeta = Boolean.TRUE;
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
                    isUpdateRepoMeta = Boolean.FALSE;
                } catch (Exception e) {
                    logger.error("openEuler upstream fetch failed, upstream:{}", upstreamDownloadUrl, e);
                    isUpdateRepoMeta = Boolean.FALSE;
                }
            }

            extendedAttrs.put(SbomRepoConstants.UPSTREAM_ATTR_KEY, upstreamUrls);
            repoMeta.setExtendedAttr(extendedAttrs);
            return isUpdateRepoMeta;
        }
    }

}