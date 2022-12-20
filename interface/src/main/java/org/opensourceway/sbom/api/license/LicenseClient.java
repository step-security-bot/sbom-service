package org.opensourceway.sbom.api.license;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.opensourceway.sbom.model.pojo.response.license.ComplianceResponse;
import org.opensourceway.sbom.model.pojo.response.license.LicenseInfo;

import java.util.List;
import java.util.Map;

public interface LicenseClient {

    boolean needRequest();

    ComplianceResponse[] getComplianceResponse(List<String> coordinates) throws JsonProcessingException;

    Map<String, LicenseInfo> getLicensesInfo();

    void scanLicenseFromPurl(String purl) throws Exception;
}
