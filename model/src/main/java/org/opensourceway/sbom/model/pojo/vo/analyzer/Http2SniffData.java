package org.opensourceway.sbom.model.pojo.vo.analyzer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record Http2SniffData(@JsonProperty(required = true) Integer pid,
                            @JsonProperty(required = true) Integer ppid,
                            @JsonProperty(required = true) String cmd,
                            @JsonProperty(required = true) List<List<String>> data) implements Serializable {}
