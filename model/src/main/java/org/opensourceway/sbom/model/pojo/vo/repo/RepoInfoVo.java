package org.opensourceway.sbom.model.pojo.vo.repo;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class RepoInfoVo implements Serializable {

    private UUID id;

    private String repoName;

    private String branch;

    private String lastCommitId;

    private String downloadLocation;

    private String specDownloadUrl;

    private List<String> upstreamDownloadUrls;

    private List<String> patchInfo;

    private List<String> packageNames;

    public RepoInfoVo() {
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public RepoInfoVo(String repoName, String branch) {
        this.repoName = repoName;
        this.branch = branch;
    }

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

    public String getLastCommitId() {
        return lastCommitId;
    }

    public void setLastCommitId(String lastCommitId) {
        this.lastCommitId = lastCommitId;
    }

    public String getDownloadLocation() {
        return downloadLocation;
    }

    public void setDownloadLocation(String downloadLocation) {
        this.downloadLocation = downloadLocation;
    }

    public String getSpecDownloadUrl() {
        return specDownloadUrl;
    }

    public void setSpecDownloadUrl(String specDownloadUrl) {
        this.specDownloadUrl = specDownloadUrl;
    }

    public List<String> getUpstreamDownloadUrls() {
        return upstreamDownloadUrls;
    }

    public void setUpstreamDownloadUrls(List<String> upstreamDownloadUrls) {
        this.upstreamDownloadUrls = upstreamDownloadUrls;
    }

    public List<String> getPatchInfo() {
        return patchInfo;
    }

    public void setPatchInfo(List<String> patchInfo) {
        this.patchInfo = patchInfo;
    }

    public List<String> getPackageNames() {
        return packageNames;
    }

    public void setPackageNames(List<String> packageNames) {
        this.packageNames = packageNames;
    }

    public void addUpstreamDownloadUrl(String upstreamDownloadUrl) {
        if (this.upstreamDownloadUrls == null) {
            this.upstreamDownloadUrls = new ArrayList<>();
        }
        this.upstreamDownloadUrls.add(upstreamDownloadUrl);
    }

    public void addUpstreamDownloadUrl(List<String> upstreamDownloadUrls) {
        if (this.upstreamDownloadUrls == null) {
            this.upstreamDownloadUrls = new ArrayList<>();
        }
        this.upstreamDownloadUrls.addAll(upstreamDownloadUrls);
    }

    public void addPatch(String patch) {
        if (this.patchInfo == null) {
            this.patchInfo = new ArrayList<>();
        }
        this.patchInfo.add(patch);
    }

    public void addPatch(List<String> patchList) {
        if (this.patchInfo == null) {
            this.patchInfo = new ArrayList<>();
        }
        this.patchInfo.addAll(patchList);
    }

    public void addPackageName(String packageName) {
        if (this.packageNames == null) {
            this.packageNames = new ArrayList<>();
        }
        this.packageNames.add(packageName);
    }

    public void addPackageName(List<String> packageNames) {
        if (this.packageNames == null) {
            this.packageNames = new ArrayList<>();
        }
        this.packageNames.addAll(packageNames);
    }

    @Override
    public String toString() {
        return "RepoInfo{" +
                "id='" + id + '\'' +
                ", repoName='" + repoName + '\'' +
                ", branch='" + branch + '\'' +
                ", lastCommitId='" + lastCommitId + '\'' +
                ", downloadLocation='" + downloadLocation + '\'' +
                ", specDownloadUrl='" + specDownloadUrl + '\'' +
                ", upstreamDownloadUrls=" + upstreamDownloadUrls +
                ", patchInfo=" + patchInfo +
                ", packageNames=" + packageNames +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RepoInfoVo repoInfo = (RepoInfoVo) o;
        return Objects.equals(repoName, repoInfo.repoName) && Objects.equals(branch, repoInfo.branch);
    }

    @Override
    public int hashCode() {
        return Objects.hash(repoName, branch);
    }
}
