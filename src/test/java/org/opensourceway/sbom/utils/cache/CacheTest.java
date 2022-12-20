package org.opensourceway.sbom.utils.cache;

import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.SbomManagerApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {SbomManagerApplication.class})
@Configuration
public class CacheTest {

    private static final Logger logger = LoggerFactory.getLogger(CacheTest.class);

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private CaffeineCacheMultiKeyTest multiKeyCache;

    @Autowired
    private CaffeineCacheReloadTest reloadCache;

    @Test
    public void testMultiKeyCache() throws InterruptedException {
        CaffeineCache multiKeyCacheMonitor = (CaffeineCache) cacheManager.getCache(CacheTestConstant.MULTI_KEY_CACHE_NAME);

        for (int i = 0; i < 5; i++) {
            multiKeyCache.getCaffeine("key1-" + i, "key2-" + i, "key3-" + i, "key4-" + i);
        }

        Thread.sleep(100);// cache size exceeded limit, will remove async
        assertCacheValue(multiKeyCache.getCaffeine("key1-4", "key2-4", "key3-4", "key4-4"), "Cache-Value-key4-4");//hit
        assertCacheValue(multiKeyCache.getCaffeine("key1-0", "key2-0", "key3-0", "key4-0"), "Cache-Value-key4-0");//missed
        assertCacheHitCount(multiKeyCacheMonitor, 1);

        assertCacheValue(multiKeyCache.getCaffeine("key1-0", "key2-0", "key3-0", "key4-0"), "Cache-Value-key4-0");//hit
        assertCacheValue(multiKeyCache.getCaffeine("key1-4", "key2-4", "key3-4", "key4-4"), "Cache-Value-key4-4");//hit
        assertCacheHitCount(multiKeyCacheMonitor, 3);

        Thread.sleep(3 * 1000);// wait cache expire
        assertCacheValue(multiKeyCache.getCaffeine("key1-0", "key2-0", "key3-0", "key4-0"), "Cache-Value-key4-0");//missed
        assertCacheValue(multiKeyCache.getCaffeine("key1-4", "key2-4", "key3-4", "key4-4"), "Cache-Value-key4-4");//missed
        assertCacheHitCount(multiKeyCacheMonitor, 3);
        assertThat(multiKeyCacheMonitor.getNativeCache().asMap().containsKey("testMulti_key1-0_key2-0")).isTrue();
        assertThat(multiKeyCacheMonitor.getNativeCache().asMap().containsKey("testMulti_key1-4_key2-4")).isTrue();

        IllegalArgumentException expectedException = null;
        try {
            multiKeyCache.getCaffeine("key1", "key2-", "key3-", "0");
        } catch (IllegalArgumentException e) {
            expectedException = e;

        }
        assertThat(expectedException).isNotNull();
        assertThat(expectedException.getMessage()).isEqualTo("Cache 'MULTI_KEY_CACHE' is configured to not allow null values but null was provided");
    }


    @Test
    public void testReloadCache() throws InterruptedException {
        CaffeineCache reloadCacheMonitor = (CaffeineCache) cacheManager.getCache(CacheTestConstant.RELOAD_CACHE_NAME);

        for (int i = 0; i < 5; i++) {
            reloadCache.getCaffeine("key-" + i);
        }

        assertCacheValue(reloadCache.getCaffeine("key-1"), "Cache-Value-key-1");//hit
        assertCacheValue(reloadCache.getCaffeine("key-2"), "Cache-Value-key-2");//hit
        assertCacheHitCount(reloadCacheMonitor, 2);

        Thread.sleep(1 * 1000);
        assertCacheValue(reloadCache.getCaffeine("key-1"), "Cache-Value-key-1");//hit
        assertCacheValue(reloadCache.getCaffeine("key-2"), "Cache-Value-key-2");//hit
        assertCacheHitCount(reloadCacheMonitor, 4);

        Thread.sleep(3 * 1000);// reload
        logger.info("{},{},{}",
                reloadCache.getCaffeine("key-1"),
                reloadCache.getCaffeine("key-2"),
                reloadCache.getCaffeine("key-3"));//cache will reload async

        assertCacheValue(reloadCache.getCaffeine("key-1"), "Cache-Value-key-1-reload");//hit
        assertCacheValue(reloadCache.getCaffeine("key-2"), "Cache-Value-key-2-reload");//hit
        assertCacheHitCount(reloadCacheMonitor, 9);
    }

    private void assertCacheValue(String actual, String expected) {
        assertThat(actual).isEqualTo(expected);
    }

    private void assertCacheHitCount(CaffeineCache multiKeyCacheMonitor, long expected) {
        assertThat(multiKeyCacheMonitor.getNativeCache().stats().hitCount()).isEqualTo(expected);
    }

}
