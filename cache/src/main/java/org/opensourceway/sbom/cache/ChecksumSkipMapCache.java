package org.opensourceway.sbom.cache;


import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Configuration
public class ChecksumSkipMapCache {
    private static final Logger logger = LoggerFactory.getLogger(ChecksumSkipMapCache.class);


    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties checksumSkipMapCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.CHECKSUM_SKIP_MAP_CACHE_NAME)
                .maximumCacheSize(1L)
                .expireAfterWrite(60 * 60L)// 1hour
                .cacheNullValue(true)
                .build();
    }

    /**
     * get checksumSkipMap value from checksumSkipMap.yml
     *
     * @param checksumSkip cacheKey(not used)，use default fixed key
     * @return {@link Map}<{@link String}, {@link List<String>}>
     */
    @Cacheable(value = {CacheConstants.CHECKSUM_SKIP_MAP_CACHE_NAME}, key = CacheConstants.CHECKSUM_SKIP_MAP_CACHE_KEY_PATTERN)
    public Map<String, List<String>> getChecksumSkipMap(String checksumSkip) {
        logger.info("get group or artifact to skip GAV from checksum.");
        try {
            ClassPathResource classPathResource = new ClassPathResource("maps/checksumSkipMap.yml");
            return new Yaml().load(classPathResource.getInputStream());
        } catch (IOException e) {
            return Map.of();
        }
    }
}
