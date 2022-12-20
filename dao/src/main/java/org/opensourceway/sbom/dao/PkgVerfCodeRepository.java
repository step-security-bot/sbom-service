package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.PkgVerfCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface PkgVerfCodeRepository extends JpaRepository<PkgVerfCode, UUID> {
    PkgVerfCode findByPkgId(UUID packageId);

    @Query(value = "SELECT A.* FROM pkg_verf_code A, package B WHERE A.pkg_id = B.id AND B.sbom_id = :sbomId",
            nativeQuery = true)
    List<PkgVerfCode> findBySbomId(UUID sbomId);

}