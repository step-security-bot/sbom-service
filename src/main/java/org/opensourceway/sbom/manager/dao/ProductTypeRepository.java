package org.opensourceway.sbom.manager.dao;

import org.opensourceway.sbom.manager.model.ProductType;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductTypeRepository extends JpaRepository<ProductType, String> {
}