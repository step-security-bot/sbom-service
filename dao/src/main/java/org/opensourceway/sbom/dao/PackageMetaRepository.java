package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.PackageMeta;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PackageMetaRepository extends JpaRepository<PackageMeta, String> {
}