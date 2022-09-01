package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.SbomElementRelationship;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SbomElementRelationshipRepository extends JpaRepository<SbomElementRelationship, UUID> {

    List<SbomElementRelationship> findBySbomId(UUID sbomId);
}