package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductConfigValue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface ProductConfigValueRepository extends JpaRepository<ProductConfigValue, UUID> {
    @Query(value = "SELECT * FROM product_config pc JOIN product_config_value pcv ON pc.id = pcv.product_config_id " +
            "WHERE pc.product_type = :productType AND pc.name = :configName AND pcv.value = :value",
            nativeQuery = true)
    Optional<ProductConfigValue> findByProductTypeAndConfigNameAndValue(String productType, String configName, String value);

    @Modifying
    @Query(value = "DELETE FROM product_config_value WHERE product_config_id = :productConfigId AND value = :value",
            nativeQuery = true)
    void deleteByProductConfigIdAndValue(UUID productConfigId, String value);
}