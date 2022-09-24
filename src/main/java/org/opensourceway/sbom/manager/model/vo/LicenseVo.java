package org.opensourceway.sbom.manager.model.vo;

import org.opensourceway.sbom.manager.model.License;

import java.io.Serializable;

public class LicenseVo implements Serializable {

    private String licenseId;

    private String licenseName;

    private boolean isLegal;

    private String licenseUrl;

    public String getLicenseId() {
        return licenseId;
    }

    public void setLicenseId(String licenseId) {
        this.licenseId = licenseId;
    }

    public String getLicenseName() {
        return licenseName;
    }

    public void setLicenseName(String licenseName) {
        this.licenseName = licenseName;
    }

    public boolean isLegal() {
        return isLegal;
    }

    public void setLegal(boolean legal) {
        isLegal = legal;
    }

    public String getLicenseUrl() {
        return licenseUrl;
    }

    public void setLicenseUrl(String licenseUrl) {
        this.licenseUrl = licenseUrl;
    }

    public static LicenseVo fromLicense(License license) {
        LicenseVo vo = new LicenseVo();

        vo.setLicenseName(license.getName());
        vo.setLicenseId(license.getSpdxLicenseId());
        vo.setLicenseUrl(license.getUrl());
        vo.setLegal(license.getIsLegal());

        return vo;
    }
}
