package org.opensourceway.sbom.model.pojo.vo.repo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ThirdPartyMetaVo {
    @JsonProperty("Name")
    private String name;

    @JsonProperty("Version Number")
    private String version;

    @JsonProperty("Upstream URL")
    private String upstreamUrl;

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public String getUpstreamUrl() {
        return upstreamUrl;
    }
}
