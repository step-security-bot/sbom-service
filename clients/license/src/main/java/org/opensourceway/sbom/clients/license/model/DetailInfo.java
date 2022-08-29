package org.opensourceway.sbom.clients.license.model;

import java.io.Serializable;
import java.util.List;

public class DetailInfo implements Serializable {

    private String pass;

    private List<String> risks;

    public String getPass() {
        return pass;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public List<String> getRisks() {
        return risks;
    }

    public void setRisks(List<String> risks) {
        this.risks = risks;
    }


}
