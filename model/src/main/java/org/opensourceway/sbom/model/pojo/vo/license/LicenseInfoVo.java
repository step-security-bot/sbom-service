package org.opensourceway.sbom.model.pojo.vo.license;

import java.io.Serializable;
import java.util.List;

public class LicenseInfoVo implements Serializable {
    private List<String> repoLicense;

    private List<String> repoLicenseLegal;


    private List<String> repoLicenseIllegal;

    private List<String> repoCopyrightLegal;

    public LicenseInfoVo(List<String> repoLicense, List<String> repoLicenseLegal, List<String> repoLicenseIllegal, List<String> repoCopyrightLegal) {
        this.repoLicense = repoLicense;
        this.repoLicenseLegal = repoLicenseLegal;
        this.repoLicenseIllegal = repoLicenseIllegal;
        this.repoCopyrightLegal = repoCopyrightLegal;
    }

    public LicenseInfoVo() {
    }

    public List<String> getRepoLicense() {
        return repoLicense;
    }

    public void setRepoLicense(List<String> repoLicense) {
        this.repoLicense = repoLicense;
    }

    public List<String> getRepoLicenseLegal() {
        return repoLicenseLegal;
    }

    public void setRepoLicenseLegal(List<String> repoLicenseLegal) {
        this.repoLicenseLegal = repoLicenseLegal;
    }

    public List<String> getRepoLicenseIllegal() {
        return repoLicenseIllegal;
    }

    public void setRepoLicenseIllegal(List<String> repoLicenseIllegal) {
        this.repoLicenseIllegal = repoLicenseIllegal;
    }

    public List<String> getRepoCopyrightLegal() {
        return repoCopyrightLegal;
    }

    public void setRepoCopyrightLegal(List<String> repoCopyrightLegal) {
        this.repoCopyrightLegal = repoCopyrightLegal;
    }
}
