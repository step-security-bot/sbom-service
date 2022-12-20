package org.opensourceway.sbom.model.pojo.response.vcs.gitee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class GiteeRepoInfo {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Owner(String login) implements Serializable {}


    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RepoInfo(Owner owner, String license, String description, String homepage,
                    @JsonProperty("html_url") String repoUrl, String name) implements Serializable {
        public RepoInfo() {
            this(new Owner(""), "", "", "", "", "");
        }
    }
}
