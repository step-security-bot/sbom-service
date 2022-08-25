package org.opensourceway.sbom.clients.license.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ComponentReport implements Serializable {

    private String purl;

    private License result;

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public License getResult() {
        return result;
    }

    public void setReference(License result) {
        this.result = result;
    }


}
