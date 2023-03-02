package org.opensourceway.sbom.cache;

import org.apache.commons.lang3.ObjectUtils;
import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.api.license.LicenseService;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.vo.license.LicenseInfoVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.utils.RepoMetaUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
public class RepoMetaLicenseCache {
    private static final Logger logger = LoggerFactory.getLogger(RepoMetaLicenseCache.class);

    @Autowired
    private LicenseClient licenseClient;

    @Autowired
    private LicenseService licenseService;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private RepoMetaUtil repoMetaUtil;

    @Bean
    public CacheProperties repoMetaLicenseCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.REPO_META_LICENSE_CACHE_NAME)
                .maximumCacheSize(5000L)
                .expireAfterAccess(60L * 60L)// 1h
                .cacheNullValue(true)
                .build();
    }


    @Cacheable(value = {CacheConstants.REPO_META_LICENSE_CACHE_NAME}, key = CacheConstants.REPO_META_LICENSE_CACHE_KEY_PATTERN)
    public RepoMeta getRepoMeta(PackageUrlVo packageUrlVo, Product product, String repo, String branch) {

        Optional<RepoMeta> repoMetaOptional = repoMetaUtil.getRepoMeta(product, packageUrlVo.getName());
        if (repoMetaOptional.isEmpty()) {
            return null;
        }
        RepoMeta repoMeta = repoMetaOptional.get();

        ExecutorService executorService = Executors.newWorkStealingPool();
        List<Callable<Boolean>> fetchTasks = Arrays.asList(
                new RepoMetaLicenseCache.FetchLicenseCallable(repoMeta, packageUrlVo, product)
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

        private final PackageUrlVo packageUrlVo;

        private final Product product;

        FetchLicenseCallable(RepoMeta repoMeta, PackageUrlVo packageUrlVo, Product product) {
            this.repoMeta = repoMeta;
            this.packageUrlVo = packageUrlVo;
            this.product = product;
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
                String purl = licenseService.getPurlsForLicense(packageUrlVo, product);
                licenseInfoVo = licenseService.getLicenseInfoVoFromPurl(List.of(purl)).get(purl);

                if (ObjectUtils.isEmpty(licenseInfoVo)) {
                    return null;
                }
            } catch (Exception e) {
                logger.error("get license for product {} repo {} branch {} from compliance failed, skip it", product.getProductType(), repoMeta.getRepoName(), repoMeta.getBranch(), e);
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

}
