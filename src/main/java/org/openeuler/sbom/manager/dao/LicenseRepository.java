package org.openeuler.sbom.manager.dao;

import org.openeuler.sbom.manager.model.License;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {


    Optional<License> findByName(String name);

    @Query(value = "SELECT A.* FROM license A, pkg_license_relp B, package C WHERE A.id = B.license_id and B.pkg_id =" +
            " C.id AND C.sbom_id = :sbomId",
            nativeQuery = true)
    List<License> findBySbomId(UUID sbomId);

    @Query(value = "SELECT A.* FROM license A, pkg_license_relp B WHERE A.id = B.license_id and B.pkg_id = :packageId",
            nativeQuery = true)
    List<License> findByPkgId(UUID packageId);
}