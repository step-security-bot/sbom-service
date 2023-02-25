package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.RepoMeta;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RepoMetaRepository extends JpaRepository<RepoMeta, UUID> {

    List<RepoMeta> findByProductType(String productType);

    @Modifying(flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<RepoMeta> deleteByProductType(String productType);

    @Modifying(flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    List<RepoMeta> deleteByProductTypeAndBranch(String productType, String branch);

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    Optional<RepoMeta> findByProductTypeAndRepoNameAndBranch(String productType, String repoName, String branch);

    @Query(value = "SELECT * FROM repo_meta WHERE product_type = :productType AND branch = :branch AND :packageName = ANY(package_names)",
            nativeQuery = true)
    List<RepoMeta> queryRepoMetaByPackageName(@Param("productType") String productType, @Param("branch") String branch, @Param("packageName") String packageName);
}
