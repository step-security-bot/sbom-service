package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.SbomElementRelationship;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface SbomElementRelationshipRepository extends JpaRepository<SbomElementRelationship, UUID> {

    List<SbomElementRelationship> findBySbomId(UUID sbomId);

    @Modifying(flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<SbomElementRelationship> deleteBySbomIdAndRelationshipType(UUID sbomId, String relationshipType);
}