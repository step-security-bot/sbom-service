package org.opensourceway.sbom.cache;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.cache.config.CacheProperties;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.ProductConfigRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductConfig;
import org.opensourceway.sbom.model.entity.ProductConfigValue;
import org.opensourceway.sbom.model.pojo.vo.sbom.ProductConfigVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Objects;

@Configuration
public class ProductConfigCache {

    private static final Logger logger = LoggerFactory.getLogger(ProductConfigCache.class);

    @Autowired
    private ProductConfigRepository productConfigRepository;

    @Autowired
    private ProductRepository productRepository;

    /**
     * @return {@link CacheProperties}
     */
    @Bean
    public CacheProperties productConfigCacheProperties() {
        return CacheProperties.builder()
                .cacheName(CacheConstants.PRODUCT_CONFIG_CACHE_NAME)
                .maximumCacheSize(1L)
                .expireAfterWrite(45 * 60L)// 45min
                .cacheNullValue(true)
                .build();
    }

    /**
     * get product configs
     *
     * @return {@link ProductConfigVo}
     */
    @Cacheable(value = {CacheConstants.PRODUCT_CONFIG_CACHE_NAME})
    public ProductConfigVo queryProductConfigByProductType(String productType) {
        logger.info("query product config for cache");
        List<ProductConfig> productConfigs = productConfigRepository.findByProductTypeOrderByOrdAsc(productType);
        List<Product> products = productRepository.queryProductByPartialAttributes("{\"productType\": \"%s\"}".formatted(productType))
                .stream().filter(product -> Objects.nonNull(product.getSbom())).toList();

        ProductConfigVo vo = new ProductConfigVo();
        fillUpProductConfigRecursively(vo, products, productConfigs, 0);
        return vo;
    }

    private void fillUpProductConfigRecursively(ProductConfigVo parentVo, List<Product> products,
                                                List<ProductConfig> productConfigs, Integer productConfigIdx) {
        products.stream()
                .map(product -> product.getAttribute().get(productConfigs.get(productConfigIdx).getName()))
                .distinct()
                .forEachOrdered(configValue -> {
                    ProductConfigVo vo = new ProductConfigVo();
                    if (productConfigIdx + 1 == productConfigs.size()) {
                        if (Objects.nonNull(configValue)) {
                            parentVo.setName(productConfigs.get(productConfigIdx).getName());
                            parentVo.setLabel(productConfigs.get(productConfigIdx).getLabel());
                            vo.setValueLabel(getConfigValueLabel(productConfigs.get(productConfigIdx), configValue));
                            parentVo.getValueToNextConfig().put(configValue, new ProductConfigVo(
                                    getConfigValueLabel(productConfigs.get(productConfigIdx), configValue)));
                        }
                        return;
                    }

                    if (Objects.isNull(configValue)) {
                        fillUpProductConfigRecursively(parentVo, products, productConfigs, productConfigIdx + 1);
                        return;
                    }

                    List<Product> satisfiedProducts = products.stream()
                            .filter(product -> StringUtils.equals(product.getAttribute().get(productConfigs.get(productConfigIdx).getName()), configValue))
                            .toList();

                    parentVo.setName(productConfigs.get(productConfigIdx).getName());
                    parentVo.setLabel(productConfigs.get(productConfigIdx).getLabel());
                    vo.setValueLabel(getConfigValueLabel(productConfigs.get(productConfigIdx), configValue));
                    fillUpProductConfigRecursively(vo, satisfiedProducts, productConfigs, productConfigIdx + 1);
                    if (Objects.isNull(vo.getName())) {
                        parentVo.getValueToNextConfig().put(configValue, new ProductConfigVo(
                                getConfigValueLabel(productConfigs.get(productConfigIdx), configValue)));
                    } else {
                        parentVo.getValueToNextConfig().put(configValue, vo);
                    }
                });
    }

    private String getConfigValueLabel(ProductConfig productConfig, String configValue) {
        return productConfig.getProductConfigValues().stream()
                .filter(productConfigValue -> StringUtils.equals(productConfigValue.getValue(), configValue))
                .findFirst()
                .map(ProductConfigValue::getLabel)
                .orElse(configValue);
    }

}