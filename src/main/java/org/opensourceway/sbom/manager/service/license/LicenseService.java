package org.opensourceway.sbom.manager.service.license;

import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;

public interface LicenseService {

    Integer getBulkRequestSize();

    boolean needRequest();

    String getPurlsForLicense(PackageUrlVo packageUrlVo, Product product);
}
