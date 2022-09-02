package org.opensourceway.sbom.clients.vcs.gitee.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class GiteeRepoInfo {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Owner(String login) implements Serializable {}


    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RepoInfo(Owner owner, String license, String description, String homepage,
                    @JsonProperty("html_url") String repoUrl) implements Serializable {
        public RepoInfo() {
            this(new Owner(""), "", "", "", "");
        }
    }
}
