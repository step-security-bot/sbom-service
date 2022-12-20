package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductStatistics;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ProductStatisticsRepository extends JpaRepository<ProductStatistics, UUID> {
    @Query(value = "SELECT * FROM product_statistics WHERE product_id = (SELECT id FROM product WHERE name = ?) " +
            "ORDER BY create_time DESC LIMIT 1",
            nativeQuery = true)
    ProductStatistics findNewestByProductName(String productName);

    @Query(value = "SELECT * FROM product_statistics WHERE product_id = (SELECT id FROM product WHERE name = :productName) " +
            "AND :startTimestamp / 1000.0 <= extract(epoch from create_time) AND extract(epoch from create_time) <= :endTimestamp / 1000.0" +
            "ORDER BY create_time ASC",
            nativeQuery = true)
    List<ProductStatistics> findByProductNameAndCreateTimeRange(String productName, Long startTimestamp, Long endTimestamp);

    @Query(value = "SELECT * FROM product_statistics WHERE product_id = (SELECT id FROM product WHERE name = :productName) " +
            "AND create_time = :createTime",
            nativeQuery = true)
    Optional<ProductStatistics> findByProductNameAndCreateTime(String productName, Timestamp createTime);
}