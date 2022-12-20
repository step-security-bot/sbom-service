package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.PkgLicenseRelp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PkgLicenseRelpRepository extends JpaRepository<PkgLicenseRelp, UUID> {
}