package org.opensourceway.sbom.cache;

import org.apache.commons.collections4.MapUtils;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.LicenseRepository;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.pojo.response.license.LicenseInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
public class LicenseObjectCache {
    private static final Logger logger = LoggerFactory.getLogger(LicenseObjectCache.class);

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private LicenseInfoMapCache licenseInfoMapCache;

    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties licenseObjectCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.LICENSE_OBJECT)
                .maximumCacheSize(1000L)
                .expireAfterWrite(60 * 60L)// 1hour
                .cacheNullValue(true)
                .build();
    }

    /**
     * get license value
     *
     * @param (licenseSpdxId,licenseLegality) cacheKey，use default fixed key
     * @return {@link License}
     */
    @Cacheable(value = {CacheConstants.LICENSE_OBJECT}, key = CacheConstants.LICENSE_OBJECT_CACHE_KEY)
    public License getLicenseCache(String licenseSpdxId, Boolean licenseLegality) {
        logger.info("get license cache for spdxId {} which is {}.", licenseSpdxId, licenseLegality);
        License license = licenseRepository.findBySpdxLicenseId(licenseSpdxId).orElse(generateNewLicense(licenseSpdxId));

        Map<String, LicenseInfo> licenseInfoMap = licenseInfoMapCache.getLicenseInfoMap(CacheConstants.LICENSE_INFO_MAP_CACHE_KEY_DEFAULT_VALUE);
        if (MapUtils.isNotEmpty(licenseInfoMap) && licenseInfoMap.containsKey(licenseSpdxId)) {
            LicenseInfo licenseInfo = licenseInfoMap.get(licenseSpdxId);
            license.setName(licenseInfo.getName());
            license.setUrl(licenseInfo.getReference());
        }

        license.setIsLegal(licenseLegality);
        licenseRepository.save(license);
        return license;
    }

    private License generateNewLicense(String lic) {
        License license = new License();
        license.setSpdxLicenseId(lic);

        return license;
    }
}
