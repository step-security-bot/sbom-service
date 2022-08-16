package org.openeuler.sbom.manager.dao;

import org.openeuler.sbom.manager.model.Sbom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface SbomRepository extends JpaRepository<Sbom, String> {

    @Query(value = "SELECT * FROM sbom WHERE product_id = (SELECT id FROM product WHERE name = :productName)",
            nativeQuery = true)
    Optional<Sbom> findByProductName(@Param("productName") String productName);
}