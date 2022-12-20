package org.opensourceway.sbom.model.pojo.response.vcs.gitee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class GiteeBranchInfo {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Commit(String sha, String url) implements Serializable {
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BranchInfo(Commit commit,
                             String name,
                             @JsonProperty("protected") String isProtected,
                             @JsonProperty("protection_url") String protectionUrl) implements Serializable {
        public BranchInfo() {
            this(new Commit("", ""), "", "", "");
        }
    }
}
