package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ProductRepository extends JpaRepository<Product, UUID> {

    @Query(value = "SELECT * FROM product WHERE attribute @> :attr\\:\\:jsonb and attribute <@ :attr\\:\\:jsonb",
            nativeQuery = true)
    Product queryProductByFullAttributes(@Param("attr") String attr);

    @Query(value = "SELECT * FROM product WHERE attribute @> :attr\\:\\:jsonb",
            nativeQuery = true)
    List<Product> queryProductByPartialAttributes(@Param("attr") String attr);

    Optional<Product> findByName(String name);

    @Query(value = "SELECT A.* FROM product A, sbom B WHERE A.id = B.product_id and B.id = :sbomId",
            nativeQuery = true)
    Product findBySbomId(UUID sbomId);

    void deleteByName(String name);
}