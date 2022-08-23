package org.openeuler.sbom.manager.dao;

import org.openeuler.sbom.manager.model.RawSbom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface RawSbomRepository extends JpaRepository<RawSbom, UUID> {

    @Query(value = "select * from raw_sbom where product_id = :#{#rawSbom.product.id} and format = :#{#rawSbom.format}" +
            " and spec = :#{#rawSbom.spec} and spec_version = :#{#rawSbom.specVersion}",
            nativeQuery = true)
    RawSbom queryRawSbom(RawSbom rawSbom);

    Optional<RawSbom> findByTaskId(UUID taskId);

    Optional<RawSbom> findByTaskIdAndTaskStatus(UUID taskId, String taskStatus);

    @Query(value = "select * from raw_sbom where task_status = 'wait' for update skip locked limit 1", nativeQuery = true)
    Optional<RawSbom> queryOneWaitingTaskWithLock();

}