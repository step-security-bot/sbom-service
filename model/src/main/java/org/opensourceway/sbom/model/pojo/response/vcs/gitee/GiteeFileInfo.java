package org.opensourceway.sbom.model.pojo.response.vcs.gitee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GiteeFileInfo(String name,
                            String type,
                            String path,
                            String url,
                            @JsonProperty("html_url") String htmlUrl,
                            @JsonProperty("download_url") String downloadUrl) implements Serializable {
}
