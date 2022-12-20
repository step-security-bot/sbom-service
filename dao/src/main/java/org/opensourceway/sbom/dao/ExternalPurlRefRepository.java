package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface ExternalPurlRefRepository extends JpaRepository<ExternalPurlRef, UUID>, JpaSpecificationExecutor<ExternalPurlRef> {

    @Query(value = "SELECT * FROM external_purl_ref WHERE category = :category AND type = :type AND pkg_id = :pkgId",
            nativeQuery = true)
    List<ExternalPurlRef> queryPackageRef(@Param("pkgId") UUID pkgId, @Param("category") String category, @Param("type") String type);

    @Query(value = "SELECT A.* FROM external_purl_ref A, package B WHERE A.pkg_id = B.id AND B.sbom_id = :sbomId",
            nativeQuery = true)
    List<ExternalPurlRef> findBySbomId(UUID sbomId);

    // TODO: 后续去除RUNTIME_DEPENDENCY_OF
    @Query(value = "SELECT * FROM external_purl_ref WHERE category = 'PACKAGE_MANAGER' \n" +
            "	AND pkg_id IN (\n" +
            "		SELECT pkg.ID FROM sbom_element_relationship ser, package pkg WHERE\n" +
            "			ser.sbom_id = :sbomId AND ser.sbom_id = pkg.sbom_id \n" +
            "			AND ser.element_id = :elementId AND ser.related_element_id = pkg.spdx_id" +
            "           AND ser.relationship_type IN ('DEPENDS_ON', 'RUNTIME_DEPENDENCY_OF'))",
            nativeQuery = true)
    List<ExternalPurlRef> queryRelationPackageRef(@Param("sbomId") UUID sbomId, @Param("elementId") String elementId);

    // TODO: 通过自定义函数简化SQL
    // TODO: 后续去除RUNTIME_DEPENDENCY_OF
    @Query(value = "SELECT * FROM external_purl_ref \n" +
            "	WHERE\n" +
            "		category = 'PACKAGE_MANAGER' \n" +
            "		AND pkg_id IN (\n" +
            "			SELECT pkg.ID FROM sbom_element_relationship ser, package pkg \n" +
            "				WHERE\n" +
            "					ser.sbom_id = :#{#condition.sbomId} \n" +
            "					AND ser.sbom_id = pkg.sbom_id \n" +
            "					AND ser.element_id = pkg.spdx_id \n" +
            "					AND ser.related_element_id IN (\n" +
            "						SELECT inner_pkg.spdx_id FROM external_purl_ref epr\n" +
            "								INNER JOIN package inner_pkg ON epr.pkg_id = inner_pkg.ID \n" +
            "							WHERE\n" +
            "								inner_pkg.sbom_id = :#{#condition.sbomId}\n" +
            "								AND epr.category = 'PACKAGE_MANAGER' \n" +
            "								AND epr.TYPE = :#{#condition.refType} \n" +
            "								AND (:#{#condition.isTypeExactly} IS NULL OR COALESCE(:#{#condition.isTypeExactly}) = 'FALSE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'type') = CAST(:#{#condition.type} AS VARCHAR)) \n" +
            "								AND (:#{#condition.isTypeExactly} IS NULL OR COALESCE(:#{#condition.isTypeExactly}) = 'TRUE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'type') LIKE CONCAT('%', :#{#condition.type}, '%')) \n" +
            "								AND (:#{#condition.isNamespaceExactly} IS NULL OR COALESCE(:#{#condition.isNamespaceExactly}) = 'FALSE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'namespace') = CAST(:#{#condition.namespace} AS VARCHAR)) \n" +
            "								AND (:#{#condition.isNamespaceExactly} IS NULL OR COALESCE(:#{#condition.isNamespaceExactly}) = 'TRUE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'namespace') LIKE CONCAT('%', :#{#condition.namespace}, '%')) \n" +
            "								AND (:#{#condition.isNameExactly} IS NULL OR COALESCE(:#{#condition.isNameExactly}) = 'FALSE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'name') = CAST(:#{#condition.name} AS VARCHAR)) \n" +
            "								AND (:#{#condition.isNameExactly} IS NULL OR COALESCE(:#{#condition.isNameExactly}) = 'TRUE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'name') LIKE CONCAT('%', :#{#condition.name}, '%')) \n" +
            "								AND (:#{#condition.isVersionExactly} IS NULL OR COALESCE(:#{#condition.isVersionExactly}) = 'FALSE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'version') = CAST(:#{#condition.version} AS VARCHAR)) \n" +
            "								AND (:#{#condition.isVersionExactly} IS NULL OR COALESCE(:#{#condition.isVersionExactly}) = 'TRUE' " +
            "                                   OR jsonb_extract_path_text(epr.purl, 'version') LIKE CONCAT('%', :#{#condition.version}, '%')) \n" +
            "					) AND ser.relationship_type IN ('DEPENDS_ON', 'RUNTIME_DEPENDENCY_OF') \n" +
            "		) ORDER BY purl",
            countProjection = "1",
            nativeQuery = true)
    Page<ExternalPurlRef> queryPackageRefByRelation(@Param("condition") ExternalPurlRefCondition condition, Pageable pageable);

    @Modifying(flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<ExternalPurlRef> deleteByPkgIdAndCategory(UUID pkgId, String category);
}