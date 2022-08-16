package org.openeuler.sbom.manager.dao;

import org.openeuler.sbom.manager.model.ExternalVulRef;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ExternalVulRefRepository extends JpaRepository<ExternalVulRef, UUID> {

    @Query(value = "SELECT A.* FROM external_vul_ref A, package B WHERE A.pkg_id = B.id AND B.sbom_id = :sbomId",
            nativeQuery = true)
    List<ExternalVulRef> findBySbomId(UUID sbomId);

    @Query(value = "with all_vul as (" +
            "select evf.*, v.vul_id v_vul_id, v.source from external_vul_ref evf join vulnerability v on evf.vul_id = v.id " +
            "where evf.pkg_id = :packageId" +
            "), oss_index as (" +
            "select * from all_vul where source = 'OSS_INDEX'" +
            "), cve_manager_dup as (" +
            "select * from all_vul where source = 'CVE_MANAGER' and v_vul_id in (select v_vul_id from oss_index)" +
            ") " +
            "select * from all_vul where id not in (select id from cve_manager_dup)",
            countQuery = "with all_vul as (" +
                    "select evf.*, v.vul_id v_vul_id, v.source from external_vul_ref evf join vulnerability v on evf.vul_id = v.id " +
                    "where evf.pkg_id = :packageId" +
                    "), oss_index as (" +
                    "select * from all_vul where source = 'OSS_INDEX'" +
                    "), cve_manager_dup as (" +
                    "select * from all_vul where source = 'CVE_MANAGER' and v_vul_id in (select v_vul_id from oss_index)" +
                    ") " +
                    "select count(1) from all_vul where id not in (select id from cve_manager_dup)",
            nativeQuery = true)
    Page<ExternalVulRef> findByPackageId(@Param("packageId") UUID packageId, Pageable pageable);
}