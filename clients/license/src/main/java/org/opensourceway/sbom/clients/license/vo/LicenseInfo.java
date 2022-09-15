package org.opensourceway.sbom.clients.license.vo;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LicenseInfo implements Serializable {

    private String id;

    private String name;

    private List<LicenseInfoText> text;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<LicenseInfoText> getText() {
        return text;
    }

    public void setText(List<LicenseInfoText> text) {
        this.text = text;
    }

}
