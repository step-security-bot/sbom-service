package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.License;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {
}