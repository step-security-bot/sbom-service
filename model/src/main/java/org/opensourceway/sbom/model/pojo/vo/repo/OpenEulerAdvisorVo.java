package org.opensourceway.sbom.model.pojo.vo.repo;

public class OpenEulerAdvisorVo {

    private String versionControl;

    private String gitUrl;

    private String url;

    private String srcRepo;

    private String tagPrefix;

    private String seperator;

    public String getVersionControl() {
        return versionControl;
    }

    public void setVersionControl(String versionControl) {
        this.versionControl = versionControl;
    }

    public String getGitUrl() {
        return gitUrl;
    }

    public void setGitUrl(String gitUrl) {
        this.gitUrl = gitUrl;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getSrcRepo() {
        return srcRepo;
    }

    public void setSrcRepo(String srcRepo) {
        this.srcRepo = srcRepo;
    }

    public String getTagPrefix() {
        return tagPrefix;
    }

    public void setTagPrefix(String tagPrefix) {
        this.tagPrefix = tagPrefix;
    }

    public String getSeperator() {
        return seperator;
    }

    public void setSeperator(String seperator) {
        this.seperator = seperator;
    }
}
