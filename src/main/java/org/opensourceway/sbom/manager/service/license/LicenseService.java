package org.opensourceway.sbom.manager.service.license;

import org.opensourceway.sbom.manager.batch.pojo.LicenseInfoVo;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;

import java.util.List;
import java.util.Map;

public interface LicenseService {

    Integer getBulkRequestSize();

    boolean needRequest();

    String getPurlsForLicense(PackageUrlVo packageUrlVo, Product product);

    Map<String, LicenseInfoVo> getLicenseInfoVoFromPurl(List<String> purls) throws Exception;
}
