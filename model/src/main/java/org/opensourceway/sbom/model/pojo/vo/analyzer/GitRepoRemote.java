package org.opensourceway.sbom.model.pojo.vo.analyzer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GitRepoRemote {
    @JacksonXmlElementWrapper(localName = "name")
    private String name;

    @JacksonXmlElementWrapper(localName = "fetch")
    private String fetch;

    @JacksonXmlElementWrapper(localName = "review")
    private String review;

    @JacksonXmlElementWrapper(localName = "revision")
    private String revision;

    public String getName() {
        return name;
    }

    public String getFetch() {
        return fetch;
    }

    public String getReview() {
        return review;
    }

    public String getRevision() {
        return revision;
    }
}
