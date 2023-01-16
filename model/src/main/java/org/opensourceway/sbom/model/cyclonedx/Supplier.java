package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;

public class Supplier {
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String name;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String url;

    public Supplier(@JsonInclude(JsonInclude.Include.NON_EMPTY) String name, @JsonInclude(JsonInclude.Include.NON_EMPTY) String url) {
        this.name = name;
        this.url = url;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
