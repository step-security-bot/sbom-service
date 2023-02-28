package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ExternalVulRef;
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
            SELECT evf.*, v.vul_id v_vul_id , coalesce(
            (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V3'),
            (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V2'),
            'UNKNOWN'
            ) severity, coalesce(
            (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V3'),
            (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V2')
            ) score, coalesce(
            (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V3'),
            (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V2')
            ) scoring_system FROM external_vul_ref evf join vulnerability v on evf.vul_id = v.id
            WHERE evf.pkg_id = :packageId
            )
            SELECT * FROM all_vul v WHERE (:severity IS NULL OR v.severity = :severity)
            AND (:vulId IS NULL OR v.v_vul_id = :vulId)
            ORDER BY v.score DESC NULLS LAST, v.v_vul_id DESC, v.scoring_system DESC NULLS LAST
            """,
            countQuery = """
                    WITH all_vul AS (
                    SELECT evf.*, v.vul_id v_vul_id, coalesce(
                    (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V3'),
                    (SELECT vs.severity FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V2'),
                    'UNKNOWN'
                    ) severity, coalesce(
                    (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V3'),
                    (SELECT vs.score FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V2')
                    ) score, coalesce(
                    (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V3'),
                    (SELECT vs.scoring_system FROM vul_score vs WHERE vs.vul_id = evf.vul_id AND vs.scoring_system = 'CVSS_V2')
                    ) scoring_system FROM external_vul_ref evf join vulnerability v on evf.vul_id = v.id
                    WHERE evf.pkg_id = :packageId
                    )
                    SELECT COUNT(1) FROM all_vul v WHERE (:severity IS NULL OR v.severity = :severity)
                    AND (:vulId IS NULL OR v.v_vul_id = :vulId)
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