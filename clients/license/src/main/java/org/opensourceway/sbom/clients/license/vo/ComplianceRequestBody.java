package org.opensourceway.sbom.clients.license.vo;

import java.io.Serializable;

public class ComplianceRequestBody implements Serializable {

    private String purl;

    public ComplianceRequestBody(String purl) {
        this.purl = purl;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }
}
