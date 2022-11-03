package org.opensourceway.sbom.pojo;

public class UpstreamInfoVo {
    private String gitUrl;

    private String versionControl;

    private String srcRepo;

    private String tagPrefix;

    private String seperator;

    public String getGitUrl() {
        return gitUrl;
    }

    public void setGitUrl(String gitUrl) {
        this.gitUrl = gitUrl;
    }

    public String getVersionControl() {
        return versionControl;
    }

    public void setVersionControl(String versionControl) {
        this.versionControl = versionControl;
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
