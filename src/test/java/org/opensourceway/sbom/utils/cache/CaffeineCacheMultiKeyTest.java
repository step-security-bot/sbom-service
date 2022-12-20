package org.opensourceway.sbom.utils.cache;

import org.opensourceway.sbom.cache.config.CacheProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CaffeineCacheMultiKeyTest {

    private static final Logger logger = LoggerFactory.getLogger(CaffeineCacheMultiKeyTest.class);

    /**
     * 多入参缓存Key，缓存对象最多3个，不允许缓存null，写入4秒后缓存失效
     */
    @Bean
    public CacheProperties multiKeyCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheTestConstant.MULTI_KEY_CACHE_NAME)
                .maximumCacheSize(3L)
                .expireAfterWrite(2L)
                .cacheNullValue(false)
                .build();
    }

    @Cacheable(value = {CacheTestConstant.MULTI_KEY_CACHE_NAME}, key = CacheTestConstant.MULTI_KEY_CACHE_KEY_PATTERN)
    public String getCaffeine(String key1, String key2, String key3, String key4) {
        if ("0".equals(key4)) {
            logger.info("[MULTI_KEY_CACHE] execute load cache value method, return null");
            return null;
        }

        logger.info("[MULTI_KEY_CACHE] execute load cache value method");
        return "Cache-Value-" + key4;
    }

}
