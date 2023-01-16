package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonCreator;

public class PatchDiff {

    private String url;

    public String getUrl() {
        return url;
    }

    @JsonCreator
    public PatchDiff(String url) {
        this.url = url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
