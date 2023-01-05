package org.opensourceway.sbom.cache.constant;

public class CacheConstants {

    public static final String DEFAULT_CACHE_KEY_PATTERN = "#key";

    public static final String LICENSE_INFO_MAP_CACHE_NAME = "licenseInfoMap";

    public static final String LICENSE_INFO_MAP_CACHE_KEY_DEFAULT_VALUE = "cacheKey";

    public static final String LICENSE_STANDARD_MAP_CACHE_NAME = "licenseStandardMap";

    public static final String LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN = "#licenseStandard";

    public static final String CHECKSUM_SKIP_MAP_CACHE_NAME = "checksumSkipMap";

    public static final String LICENSE_OBJECT = "licenseObject";

    public static final String LICENSE_OBJECT_CACHE_KEY = "#licenseSpdxId + '_' + #licenseLegality";

    public static final String CHECKSUM_SKIP_MAP_CACHE_KEY_PATTERN = "#checksumSkip";

    public static final String PRODUCT_CONFIG_CACHE_NAME = "productConfig";

    public static final String OPENEULER_REPO_BRANCHES_CACHE_NAME = "openEulerRepoBranches";

    public static final String OPENEULER_REPO_BRANCHES_CACHE_KEY_PATTERN = "'repo_branches_' + #org + '_' + #repo";

    public static final String OPENEULER_REPO_META_CACHE_NAME = "openEulerRepoMeta";

    public static final String OPENEULER_REPO_META_CACHE_KEY_PATTERN = "'openeuler_repo_meta_' + #repo + '_' + #branch";

    public static final String OPENHARMONY_THIRD_PARTY_REPO_META_CACHE_NAME = "OpenHarmonyThirdPartyRepoMeta";

    public static final String REPO_META_LICENSE_CACHE_NAME = "repoMetaLicense";

    public static final String REPO_META_LICENSE_CACHE_KEY_PATTERN = "'repo_meta_license_' + #product.attribute['productType'] + #repo + '_' + #branch";

}
