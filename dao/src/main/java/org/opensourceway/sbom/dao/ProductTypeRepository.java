package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface ProductTypeRepository extends JpaRepository<ProductType, String> {
    @Modifying
    @Query(value = "LOCK TABLE product_type", nativeQuery = true)
    void lockTable();
}