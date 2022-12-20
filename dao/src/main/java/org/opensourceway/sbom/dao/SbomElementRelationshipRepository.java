package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SbomElementRelationshipRepository extends JpaRepository<SbomElementRelationship, UUID> {

    List<SbomElementRelationship> findBySbomId(UUID sbomId);

    @Modifying(flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<SbomElementRelationship> deleteBySbomIdAndRelationshipType(UUID sbomId, String relationshipType);

    @Query(value = "SELECT * FROM sbom_element_relationship WHERE " +
            "sbom_id = :#{#relationship.sbom.id} AND element_id = :#{#relationship.elementId} " +
            "AND related_element_id = :#{#relationship.relatedElementId} AND relationship_type = :#{#relationship.relationshipType}",
            nativeQuery = true)
    Optional<SbomElementRelationship> querySbomElementRelationship(SbomElementRelationship relationship);

}