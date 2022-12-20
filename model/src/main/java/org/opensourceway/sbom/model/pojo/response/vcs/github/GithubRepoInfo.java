package org.opensourceway.sbom.model.pojo.response.vcs.github;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class GithubRepoInfo {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Owner(String login) implements Serializable {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record License(String name) implements Serializable {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RepoInfo(Owner owner, License license, String description, String homepage,
                    @JsonProperty("clone_url") String repoUrl) implements Serializable {
        public RepoInfo() {
            this(new Owner(""), new License(""), "", "", "");
        }
    }
}
