package org.opensourceway.sbom.utils.cache;

import com.github.benmanes.caffeine.cache.CacheLoader;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CaffeineCacheReloadTest {

    private static final Logger logger = LoggerFactory.getLogger(CaffeineCacheReloadTest.class);

    /**
     * 单入参缓存Key，缓存对象最多10个，允许缓存null，访问6秒后缓存失效，11秒后自动刷新缓存值
     */
    @Bean
    public CacheProperties reloadCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheTestConstant.RELOAD_CACHE_NAME)
                .maximumCacheSize(5L)
//                .expireAfterWrite(2L)
                .refreshAfterWrite(2L)
                .cacheNullValue(true)
                .cacheLoader(new CaffeineCacheReloadTest().cacheLoader())
                .build();
    }

    @Cacheable(value = {CacheTestConstant.RELOAD_CACHE_NAME}, key = CacheTestConstant.RELOAD_CACHE_KEY_PATTERN)
    public String getCaffeine(String id) {
        return "Cache-Value-" + id;
    }

    public CacheLoader<String, String> cacheLoader() {
        return new CacheLoader<>() {

            @Override
            public @Nullable String load(@NonNull String key) {
                logger.info("[RELOAD_CACHE] missed cache, load key:{}", key);
                return getCaffeine(key);
            }

            @Override
            public String reload(@NonNull String key, @NonNull String oldValue) {
                logger.info("[RELOAD_CACHE] reload cache, key:{}, oldValue:{}", key, oldValue);
                return oldValue + "-reload";
            }
        };
    }

}
