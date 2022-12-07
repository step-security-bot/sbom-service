package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.PackageMeta;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PackageMetaRepository extends JpaRepository<PackageMeta, UUID> {
    Optional<PackageMeta> findByChecksum(String checksum);
}