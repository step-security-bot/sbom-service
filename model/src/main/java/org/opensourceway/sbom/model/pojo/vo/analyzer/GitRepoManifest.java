package org.opensourceway.sbom.model.pojo.vo.analyzer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import java.util.List;

/**
 * According to <a href="https://girret.googlesource.com/git-repo/+/master/docs/manifest-format.md">manifest-format</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class GitRepoManifest {
    @JacksonXmlProperty(localName = "default")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<GitRepoDefault> manifestDefault;

    @JacksonXmlProperty(localName = "remote")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<GitRepoRemote> remotes;

    @JacksonXmlProperty(localName = "project")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<GitRepoProject> projects;

    public List<GitRepoDefault> getManifestDefault() {
        return manifestDefault;
    }

    public List<GitRepoRemote> getRemotes() {
        return remotes;
    }

    public List<GitRepoProject> getProjects() {
        return projects;
    }
}
