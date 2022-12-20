package org.opensourceway.sbom.dao;

import org.opensourceway.sbom.model.entity.ProductType;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductTypeRepository extends JpaRepository<ProductType, String> {
}