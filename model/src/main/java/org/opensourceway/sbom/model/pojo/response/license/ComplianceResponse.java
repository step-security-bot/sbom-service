package org.opensourceway.sbom.model.pojo.response.license;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ComplianceResponse implements Serializable {

    private String purl;

    private LicenseAndCopyright result;

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public LicenseAndCopyright getResult() {
        return result;
    }

    public void setReference(LicenseAndCopyright result) {
        this.result = result;
    }


}
