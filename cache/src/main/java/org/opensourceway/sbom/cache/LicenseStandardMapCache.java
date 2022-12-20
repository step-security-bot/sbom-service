package org.opensourceway.sbom.cache;

import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.Map;

import static org.opensourceway.sbom.utils.YamlUtil.LoadYamlFromInputStream;

@Configuration
public class LicenseStandardMapCache {

    private static final Logger logger = LoggerFactory.getLogger(LicenseStandardMapCache.class);


    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties licenseStandardMapCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.LICENSE_STANDARD_MAP_CACHE_NAME)
                .maximumCacheSize(1L)
                .expireAfterWrite(24 * 60 * 60L)// 1day
                .cacheNullValue(true)
                .build();
    }

    /**
     * get licenseStandardMap value from licenseMap.yml
     *
     * @param licenseStandard cacheKey(not used)，use default fixed key
     * @return {@link Map}<{@link String}, {@link String}>
     */
    @Cacheable(value = {CacheConstants.LICENSE_STANDARD_MAP_CACHE_NAME}, key = CacheConstants.LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN)
    public Map<String, String> getLicenseStandardMap(String licenseStandard) {
        logger.info("get standard ID for license.");
        try {
            ClassPathResource classPathResource = new ClassPathResource("maps/licenseMap.yml");
            return LoadYamlFromInputStream(classPathResource.getInputStream());
        } catch (IOException e) {
            return Map.of();
        }
    }
}
