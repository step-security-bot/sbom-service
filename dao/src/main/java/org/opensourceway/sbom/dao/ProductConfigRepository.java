package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ProductConfigRepository extends JpaRepository<ProductConfig, UUID> {
    @Query(value = "SELECT * FROM product_config WHERE product_type = ? ORDER BY ord ASC",
            nativeQuery = true)
    List<ProductConfig> findByProductTypeOrderByOrdAsc(String productType);

    @Query(value = "SELECT * FROM product_config WHERE product_type = :productType and name = :name",
            nativeQuery = true)
    Optional<ProductConfig> findByProductTypeAndName(String productType, String name);
}