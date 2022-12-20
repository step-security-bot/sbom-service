package org.opensourceway.sbom.model.pojo.vo.repo;

import java.io.Serializable;
import java.util.Map;

public class RepoMetaVo implements Serializable {

    private String repoName;

    private String branch;

    private String downloadLocation;

    private String[] packageNames;

    private Map<String, Object> extendedAttr;

    public String getRepoName() {
        return repoName;
    }

    public void setRepoName(String repoName) {
        this.repoName = repoName;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getDownloadLocation() {
        return downloadLocation;
    }

    public void setDownloadLocation(String downloadLocation) {
        this.downloadLocation = downloadLocation;
    }

    public String[] getPackageNames() {
        return packageNames;
    }

    public void setPackageNames(String[] packageNames) {
        this.packageNames = packageNames;
    }

    public Map<String, Object> getExtendedAttr() {
        return extendedAttr;
    }

    public void setExtendedAttr(Map<String, Object> extendedAttr) {
        this.extendedAttr = extendedAttr;
    }
}
