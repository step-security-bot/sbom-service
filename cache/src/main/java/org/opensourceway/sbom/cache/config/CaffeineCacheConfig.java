package org.opensourceway.sbom.cache.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;


/**
 * CaffeineCache启动配置类
 * <p>
 * 通过定义CaffeineCacheConfig类型的Bean，即可新增Caffeine的缓存分类（通过定义CaffeineCacheConfig类型的Bean中cacheName必填）
 * <p>
 * Example:
 * <blockquote>
 * <pre>
 *  &#064;Bean
 *  public CacheProperties testCacheProperties() {
 *      return CacheProperties.builder().cacheName("testName").maximumCacheSize(100L).expireAfterWrite(6L).cacheNullValue(true).build();
 *  }
 * </pre>
 * </blockquote>
 */
@Configuration
@EnableCaching
public class CaffeineCacheConfig {
    private static final Long DEFAULT_MAX_SIZE_LONG = 1000L;

    @Bean
    public CacheManager cacheManager(@Autowired(required = false) List<CacheProperties<String,Object>> cachePropertiesList) {
        SimpleCacheManager cacheManager = new SimpleCacheManager();
        cacheManager.setCaches(initCachesByProperties(cachePropertiesList));
        return cacheManager;
    }

    private ArrayList<CaffeineCache> initCachesByProperties(List<CacheProperties<String,Object>> cachePropertiesList) {
        ArrayList<CaffeineCache> caches = new ArrayList<>();
        if (CollectionUtils.isEmpty(cachePropertiesList)) {
            return caches;
        }

        for (CacheProperties cacheProperties : cachePropertiesList) {
            Cache<Object, Object> cacheConfig;

            Caffeine<Object, Object> cacheConfigBuilder = Caffeine.newBuilder();
            cacheConfigBuilder.recordStats();
            cacheConfigBuilder.maximumSize(Optional.ofNullable(cacheProperties.getMaximumCacheSize()).orElse(DEFAULT_MAX_SIZE_LONG));
            if (cacheProperties.getInitialCacheSize() != null) {
                cacheConfigBuilder.initialCapacity(cacheProperties.getInitialCacheSize());
            }
            if (cacheProperties.getExpireAfterAccess() != null) {
                cacheConfigBuilder.expireAfterAccess(cacheProperties.getExpireAfterAccess(), TimeUnit.SECONDS);
            }
            if (cacheProperties.getExpireAfterWrite() != null) {
                cacheConfigBuilder.expireAfterWrite(cacheProperties.getExpireAfterWrite(), TimeUnit.SECONDS);
            }
            if (cacheProperties.getRefreshAfterWrite() != null && cacheProperties.getCacheLoader() != null) {
                cacheConfigBuilder.refreshAfterWrite(cacheProperties.getRefreshAfterWrite(), TimeUnit.SECONDS);
                cacheConfig = cacheConfigBuilder.build(cacheProperties.getCacheLoader());
            } else {
                cacheConfig = cacheConfigBuilder.build();
            }
            caches.add(new CaffeineCache(cacheProperties.getCacheName(), cacheConfig, cacheProperties.getCacheNullValue()));
        }
        return caches;
    }

}
