package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.Sbom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface SbomRepository extends JpaRepository<Sbom, UUID> {

    @Query(value = "SELECT * FROM sbom WHERE product_id = (SELECT id FROM product WHERE name = :productName)",
            nativeQuery = true)
    Optional<Sbom> findByProductName(@Param("productName") String productName);
}