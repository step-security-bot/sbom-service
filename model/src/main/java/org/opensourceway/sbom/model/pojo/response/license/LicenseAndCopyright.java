package org.opensourceway.sbom.model.pojo.response.license;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LicenseAndCopyright implements Serializable {

    @JsonProperty("is_sca")
    private String isSca;

    @JsonProperty("repo_license")
    private List<String> repoLicense;

    @JsonProperty("repo_license_legal")
    private List<String> repoLicenseLegal;

    @JsonProperty("repo_license_illegal")
    private List<String> repoLicenseIllegal;

    @JsonProperty("repo_copyright_legal")
    private List<String> repoCopyrightLegal;

    @JsonProperty("repo_copyright_illegal")
    private List<String> repoCopyrightIllegal;

    public String getIsSca() {
        return isSca;
    }

    public void setIsSca(String isSca) {
        this.isSca = isSca;
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

    public List<String> getRepoCopyrightIllegal() {
        return repoCopyrightIllegal;
    }

    public void setRepoCopyrightIllegal(List<String> repoCopyrightIllegal) {
        this.repoCopyrightIllegal = repoCopyrightIllegal;
    }


}
