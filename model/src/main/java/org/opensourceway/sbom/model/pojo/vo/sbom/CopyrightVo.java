package org.opensourceway.sbom.model.pojo.vo.sbom;

import java.io.Serializable;

public class CopyrightVo implements Serializable {
    private String organization;

    private String startYear;

    private String additionalInfo;

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getStartYear() {
        return startYear;
    }

    public void setStartYear(String startYear) {
        this.startYear = startYear;
    }

    public String getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
    }
}
