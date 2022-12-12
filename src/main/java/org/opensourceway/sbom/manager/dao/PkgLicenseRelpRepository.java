package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.PkgLicenseRelp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PkgLicenseRelpRepository extends JpaRepository<PkgLicenseRelp, UUID> {
}