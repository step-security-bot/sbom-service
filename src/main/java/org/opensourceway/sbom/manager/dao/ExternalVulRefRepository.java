package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.ExternalVulRef;
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

    @Query(value = "with all_vul as ( " +
            "select evf.*, v.vul_id v_vul_id, v.source from external_vul_ref evf join vulnerability v on evf.vul_id = v.id  " +
            "where evf.pkg_id = :packageId " +
            "), oss_index as ( " +
            "select * from all_vul where source = 'OSS_INDEX' " +
            "), cve_manager_dup as ( " +
            "select * from all_vul where source = 'CVE_MANAGER' and v_vul_id in (select v_vul_id from oss_index) " +
            "), uni_vul as ( " +
            "select * from all_vul where id not in (select id from cve_manager_dup) " +
            "), vul_with_max_scoring_system as ( " +
            "select vul_id, max(scoring_system) ss from vul_score vs where vs.vul_id in (select vul_id from all_vul) group by vul_id " +
            "), uni_vul_score as ( " +
            "select vs.* from vul_score vs join vul_with_max_scoring_system tmp on vs.vul_id = tmp.vul_id and vs.scoring_system = tmp.ss " +
            ") " +
            "select uv.* from uni_vul uv join uni_vul_score uvs on uv.vul_id = uvs.vul_id order by uvs.score desc, uv.v_vul_id desc, uvs.scoring_system desc",
            countQuery = "with all_vul as ( " +
                    "select evf.*, v.vul_id v_vul_id, v.source from external_vul_ref evf join vulnerability v on evf.vul_id = v.id  " +
                    "where evf.pkg_id = :packageId " +
                    "), oss_index as ( " +
                    "select * from all_vul where source = 'OSS_INDEX' " +
                    "), cve_manager_dup as ( " +
                    "select * from all_vul where source = 'CVE_MANAGER' and v_vul_id in (select v_vul_id from oss_index) " +
                    "), uni_vul as ( " +
                    "select * from all_vul where id not in (select id from cve_manager_dup) " +
                    "), vul_with_max_scoring_system as ( " +
                    "select vul_id, max(scoring_system) ss from vul_score vs where vs.vul_id in (select vul_id from all_vul) group by vul_id " +
                    "), uni_vul_score as ( " +
                    "select vs.* from vul_score vs join vul_with_max_scoring_system tmp on vs.vul_id = tmp.vul_id and vs.scoring_system = tmp.ss " +
                    ") " +
                    "select count(1) from uni_vul uv join uni_vul_score uvs on uv.vul_id = uvs.vul_id",
            nativeQuery = true)
    Page<ExternalVulRef> findByPackageId(@Param("packageId") UUID packageId, Pageable pageable);
}