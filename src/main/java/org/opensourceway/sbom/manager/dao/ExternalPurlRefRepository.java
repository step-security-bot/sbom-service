package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ExternalPurlRefRepository extends JpaRepository<ExternalPurlRef, UUID>, JpaSpecificationExecutor<ExternalPurlRef> {

    @Query(value = "SELECT * FROM external_purl_ref WHERE category = :category AND type = :type AND pkg_id = :pkgId",
            nativeQuery = true)
    List<ExternalPurlRef> queryPackageRef(@Param("pkgId") UUID pkgId, @Param("category") String category, @Param("type") String type);

    @Query(value = "SELECT A.* FROM external_purl_ref A, package B WHERE A.pkg_id = B.id AND B.sbom_id = :sbomId",
            nativeQuery = true)
    List<ExternalPurlRef> findBySbomId(UUID sbomId);

    @Query(value = "SELECT * FROM external_purl_ref WHERE category = 'PACKAGE_MANAGER' \n" +
            "	AND pkg_id IN (\n" +
            "		SELECT pkg.ID FROM sbom_element_relationship ser, package pkg WHERE\n" +
            "			ser.sbom_id = :sbomId AND ser.sbom_id = pkg.sbom_id \n" +
            "			AND ser.element_id = :elementId AND ser.related_element_id = pkg.spdx_id)",
            nativeQuery = true)
    List<ExternalPurlRef> queryRelationPackageRef(UUID sbomId,String elementId);

}