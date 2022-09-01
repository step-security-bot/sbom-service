package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.VulScore;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface VulScoreRepository extends JpaRepository<VulScore, UUID> {
}