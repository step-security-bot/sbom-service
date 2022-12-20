package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.VulScore;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface VulScoreRepository extends JpaRepository<VulScore, UUID> {
}