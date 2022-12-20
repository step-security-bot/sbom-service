package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.File;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface FileRepository extends JpaRepository<File, UUID> {

    List<File> findBySbomId(UUID sbomId);

    List<File> findBySbomIdAndSpdxId(UUID sbomId, String spdxId);

    @Query(value = "select * from file where sbom_id = :sbomId",
            countProjection = "1",
            nativeQuery = true)
    Page<File> findFilesBySbomIdForPage(@Param("sbomId") UUID sbomId, Pageable pageable);

    @Query(value = "SELECT * FROM file WHERE sbom_id = :sbomId\n" +
            "	AND file_types [ 1 ] = 'SOURCE' \n" +
            "	AND spdx_id IN (\n" +
            "		SELECT element_id FROM sbom_element_relationship WHERE sbom_id = :sbomId\n" +
            "			AND related_element_id = :packageElemId\n" +
            "			AND relationship_type = 'PATCH_APPLIED' )",
            nativeQuery = true)
    List<File> findPatchesInfo(@Param("sbomId") UUID sbomId, @Param("packageElemId") String packageElemId);

    @Modifying(flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<File> deleteBySbomId(UUID sbomId);

}