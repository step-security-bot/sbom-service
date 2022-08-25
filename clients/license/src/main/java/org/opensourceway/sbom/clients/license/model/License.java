package org.opensourceway.sbom.clients.license.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class License implements Serializable {

    @JsonProperty("repo_license_legal")
    private RepoLegal repoLicenseLegal;

    @JsonProperty("repo_copyright_legal")
    private RepoLegal repoCopyrightLegal;

    public RepoLegal getRepoLicenseLegal() {
        return repoLicenseLegal;
    }

    public void setRepoLicenseLegal(RepoLegal repoLicenseLegal) {
        this.repoLicenseLegal = repoLicenseLegal;
    }

    public RepoLegal getRepoCopyrightLegal() {
        return repoCopyrightLegal;
    }

    public void setRepoCopyrightLegal(RepoLegal repoCopyrightLegal) {
        this.repoCopyrightLegal = repoCopyrightLegal;
    }


}
