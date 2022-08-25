package org.openeuler.sbom.manager.dao;

import org.openeuler.sbom.manager.model.License;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {

//    List<License> findBySbomId(UUID sbomId);
//
    License findByName(String name);
}