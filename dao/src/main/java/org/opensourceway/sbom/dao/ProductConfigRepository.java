package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface ProductConfigRepository extends JpaRepository<ProductConfig, UUID> {
    @Query(value = "SELECT * FROM product_config WHERE product_type = ? ORDER BY ord ASC",
            nativeQuery = true)
    List<ProductConfig> findByProductTypeOrderByOrdAsc(String productType);
}