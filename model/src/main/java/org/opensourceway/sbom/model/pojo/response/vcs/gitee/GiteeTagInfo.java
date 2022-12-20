package org.opensourceway.sbom.model.pojo.response.vcs.gitee;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GiteeTagInfo(String name) implements Serializable {
}
