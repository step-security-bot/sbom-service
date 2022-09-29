package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.RepoMeta;
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

    Optional<RepoMeta> findByProductTypeAndRepoNameAndBranch(String productType, String repoName, String branch);

    @Query(value = "SELECT * FROM repo_meta WHERE product_type = :productType AND :packageName = ANY(package_names)",
            nativeQuery = true)
    Optional<RepoMeta> queryRepoMetaByPackageName(@Param("productType") String productType, @Param("packageName") String packageName);

}
