package org.opensourceway.sbom.model.pojo.response.vcs.gitlab;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class GitlabRepoInfo {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Owner(String name) implements Serializable {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record License(String name) implements Serializable {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RepoInfo(Owner owner, License license, String description, @JsonProperty("web_url") String homepage,
                    @JsonProperty("http_url_to_repo") String repoUrl) implements Serializable {
        public RepoInfo() {
            this(new Owner(""), new License(""), "", "", "");
        }
    }
}
