package org.opensourceway.sbom.model.pojo.vo.analyzer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GitRepoDefault {
    @JacksonXmlElementWrapper(localName = "remote")
    private String remote;

    @JacksonXmlElementWrapper(localName = "revision")
    private String revision;

    @JacksonXmlElementWrapper(localName = "upstream")
    private String upstream;

    public String getRemote() {
        return remote;
    }

    public String getRevision() {
        return revision;
    }

    public String getUpstream() {
        return upstream;
    }
}
