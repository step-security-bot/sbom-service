package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.VulReference;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface VulReferenceRepository extends JpaRepository<VulReference, UUID> {
}