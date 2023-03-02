package org.opensourceway.sbom.utils;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class RepoMetaUtil {

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    public Optional<RepoMeta> getRepoMeta(Product product, String pkgName) {
        String productType = product.getProductType();
        String productVersion = product.getProductVersion();
        if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENEULER_NAME)) {
            return repoMetaRepository.queryRepoMetaByPackageName(productType, productVersion, pkgName)
                    .stream().findFirst();
        }
        return Optional.empty();
    }

    public Optional<RepoMeta> getRepoMeta(String productType, String productVersion, String productName, String pkgName) {
        if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENEULER_NAME)) {
            return repoMetaRepository.queryRepoMetaByPackageName(productType, productVersion, pkgName)
                    .stream().findFirst();
        }
        return Optional.empty();
    }
}
