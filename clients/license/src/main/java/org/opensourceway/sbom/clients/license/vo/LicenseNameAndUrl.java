package org.opensourceway.sbom.clients.license.vo;

import com.fasterxml.jackson.annotation.JsonClassDescription;

@JsonClassDescription
public class LicenseNameAndUrl {
    private String name;

    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
