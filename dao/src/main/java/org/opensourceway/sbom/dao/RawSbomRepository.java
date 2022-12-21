package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.RawSbom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface RawSbomRepository extends JpaRepository<RawSbom, UUID> {

    @Query(value = "select * from raw_sbom where product_id = :#{#rawSbom.product.id} and value_type = :#{#rawSbom.valueType}",
            nativeQuery = true)
    RawSbom queryRawSbom(RawSbom rawSbom);

    Optional<RawSbom> findByTaskId(UUID taskId);

    Optional<RawSbom> findByTaskIdAndTaskStatus(UUID taskId, String taskStatus);

    @Query(value = "select * from raw_sbom where task_status = :taskStatus for update skip locked limit 1", nativeQuery = true)
    Optional<RawSbom> queryOneTaskByTaskStatusWithLock(String taskStatus);

}