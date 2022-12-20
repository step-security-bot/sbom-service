package org.opensourceway.sbom.cache;

import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.model.pojo.response.license.LicenseInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
public class LicenseInfoMapCache {

    private static final Logger logger = LoggerFactory.getLogger(LicenseInfoMapCache.class);

    @Autowired
    private LicenseClient licenseClient;

    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties licenseInfoMapCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.LICENSE_INFO_MAP_CACHE_NAME)
                .maximumCacheSize(1L)
                .expireAfterWrite(45 * 60L)// 45min
                .cacheNullValue(true)
                .build();
    }

    /**
     * get licenseInfoMap value from remote licenses.json
     *
     * @param key cacheKey(not used)，use default fixed key
     * @return {@link Map}<{@link String}, {@link LicenseInfo}>
     */
    @Cacheable(value = {CacheConstants.LICENSE_INFO_MAP_CACHE_NAME}, key = CacheConstants.DEFAULT_CACHE_KEY_PATTERN)
    public Map<String, LicenseInfo> getLicenseInfoMap(String key) {
        logger.info("load license info map from remote for cache");
        return licenseClient.getLicensesInfo();
    }

}