package org.opensourceway.sbom.analyzer.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GitData(
        String url, @JsonProperty("commit_id") String commitId,
        @JsonProperty("version_string") String versionString, String tag) implements Serializable {}
