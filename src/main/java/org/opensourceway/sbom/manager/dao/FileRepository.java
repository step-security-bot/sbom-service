package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.File;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface FileRepository extends JpaRepository<File, UUID> {

    List<File> findBySbomId(UUID sbomId);

    List<File> findBySbomIdAndSpdxId(UUID sbomId, String spdxId);

    @Query(value = "select * from file where sbom_id = :sbomId",
            countProjection = "1",
            nativeQuery = true)
    Page<File> findFilesBySbomIdForPage(@Param("sbomId") UUID sbomId, Pageable pageable);

}