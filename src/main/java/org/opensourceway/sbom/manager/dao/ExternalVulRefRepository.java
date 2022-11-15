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

    @Query(value = """
            WITH all_vul AS (
            SELECT evf.*, v.vul_id v_vul_id, v.source FROM external_vul_ref evf join vulnerability v on evf.vul_id = v.id
            WHERE evf.pkg_id = :packageId
            ), oss_index AS (
            SELECT * FROM all_vul WHERE source = 'OSS_INDEX'
            ), cve_manager_dup AS (
            SELECT * FROM all_vul WHERE source = 'CVE_MANAGER' AND v_vul_id in (SELECT v_vul_id FROM oss_index)
            ), uni_vul AS (
            SELECT *, coalesce(
            (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS3'),
            (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS2'),
            'UNKNOWN'
            ) severity, coalesce(
            (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS3'),
            (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS2')
            ) score, coalesce(
            (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS3'),
            (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS2')
            ) scoring_system FROM all_vul v WHERE id NOT IN (SELECT id FROM cve_manager_dup)
            )
            SELECT * FROM uni_vul uv WHERE (:severity IS NULL OR uv.severity = :severity)
            AND (:vulId IS NULL OR uv.v_vul_id = :vulId)
            ORDER BY uv.score DESC NULLS LAST, uv.v_vul_id DESC, uv.scoring_system DESC NULLS LAST
            """,
            countQuery = """
            WITH all_vul AS (
            SELECT evf.*, v.vul_id v_vul_id, v.source FROM external_vul_ref evf join vulnerability v on evf.vul_id = v.id
            WHERE evf.pkg_id = :packageId
            ), oss_index AS (
            SELECT * FROM all_vul WHERE source = 'OSS_INDEX'
            ), cve_manager_dup AS (
            SELECT * FROM all_vul WHERE source = 'CVE_MANAGER' AND v_vul_id in (SELECT v_vul_id FROM oss_index)
            ), uni_vul AS (
            SELECT *, coalesce(
            (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS3'),
            (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS2'),
            'UNKNOWN'
            ) severity, coalesce(
            (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS3'),
            (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS2')
            ) score, coalesce(
            (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS3'),
            (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = v.vul_id AND vs.scoring_system = 'CVSS2')
            ) scoring_system FROM all_vul v WHERE id NOT IN (SELECT id FROM cve_manager_dup)
            )
            SELECT COUNT(1) FROM uni_vul uv WHERE (:severity IS NULL OR uv.severity = :severity)
            AND (:vulId IS NULL OR uv.v_vul_id = :vulId)
            """,
            nativeQuery = true)
    Page<ExternalVulRef> findByPackageIdAndSeverityAndVulId(@Param("packageId") UUID packageId,
                                                            @Param("severity") String severity,
                                                            @Param("vulId") String vulId,
                                                            Pageable pageable);

    @Query(value = """
            SELECT evr.* FROM external_vul_ref evr JOIN package p ON evr.pkg_id = p.id JOIN vulnerability v ON evr.vul_id = v.id
            WHERE p.sbom_id = (SELECT id FROM sbom WHERE product_id = (SELECT id FROM product WHERE name = :productName))
            AND v.vul_id = :vulId
            """,
            nativeQuery = true)
    List<ExternalVulRef> findByProductNameAndVulId(String productName, String vulId);
}