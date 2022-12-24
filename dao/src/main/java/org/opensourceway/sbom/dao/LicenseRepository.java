package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.License;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {

    @Query(value = "SELECT * from license where spdx_license_id = :name",
            nativeQuery = true)
    Optional<License> findBySpdxLicenseId(String name);

    @Query(value = "SELECT A.* FROM license A, pkg_license_relp B, package C WHERE A.id = B.license_id and B.pkg_id =" +
            " C.id AND C.sbom_id = :sbomId",
            nativeQuery = true)
    List<License> findBySbomId(UUID sbomId);

    @Query(value = "SELECT A.* FROM license A, pkg_license_relp B WHERE A.id = B.license_id and B.pkg_id = :packageId",
            nativeQuery = true)
    List<License> findByPkgId(UUID packageId);

    @Query(value = "SELECT A.spdx_license_id AS licenseId, A.\"name\" licenseName,A.is_legal isLegal,A.url licenseUrl,COUNT(A.*) FROM license A, pkg_license_relp B, package C, sbom D, product E WHERE A.id = " +
            "B.license_id AND B.pkg_id = C.id AND C.sbom_id = D.id AND D.product_id = E.id AND E.name = :productName " +
            "AND (:license IS NULL OR A.spdx_license_id = :license) AND (:isLegal IS NULL OR A.is_legal = :isLegal) GROUP BY A.spdx_license_id, A.\"name\",A.is_legal,A.url",
            nativeQuery = true)
    Page<Map> findUniversal(String productName, String license, Boolean isLegal, Pageable pageable);

}