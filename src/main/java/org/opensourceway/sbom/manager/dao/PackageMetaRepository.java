package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.PackageMeta;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PackageMetaRepository extends JpaRepository<PackageMeta, String> {
}