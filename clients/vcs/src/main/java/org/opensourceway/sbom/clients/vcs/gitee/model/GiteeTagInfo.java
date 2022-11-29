package org.opensourceway.sbom.clients.vcs.gitee.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GiteeTagInfo(String name) implements Serializable {
}
