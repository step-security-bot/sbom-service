package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.VulReference;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface VulReferenceRepository extends JpaRepository<VulReference, UUID> {
}