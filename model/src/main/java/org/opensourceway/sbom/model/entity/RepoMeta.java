package org.opensourceway.sbom.model.entity;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.Table;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(indexes = {
        @Index(name = "repo_name_uk", columnList = "product_type, repo_name, branch", unique = true)
})
@TypeDefs({
        @TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
})
public class RepoMeta {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @Column(columnDefinition = "TEXT", name = "product_type")
    private String productType;

    @Column(columnDefinition = "TEXT", name = "repo_name")
    private String repoName;

    @Column(columnDefinition = "TEXT")
    private String branch;

    @Column(name = "download_location")
    private String downloadLocation;

    @Column(name = "spec_download_url")
    private String specDownloadUrl;

    @Column(columnDefinition = "TEXT[]", name = "upstream_download_urls")
    private String[] upstreamDownloadUrls;

    @Column(columnDefinition = "TEXT[]", name = "patch_info")
    private String[] patchInfo;

    @Column(columnDefinition = "TEXT[]", name = "package_names")
    private String[] packageNames;

    @Column(columnDefinition = "JSONB")
    @Type(type = "jsonb")
    private Map<String, Object> extendedAttr;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getProductType() {
        return productType;
    }

    public void setProductType(String productType) {
        this.productType = productType;
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

    public String[] getUpstreamDownloadUrls() {
        return upstreamDownloadUrls;
    }

    public void setUpstreamDownloadUrls(String[] upstreamDownloadUrls) {
        this.upstreamDownloadUrls = upstreamDownloadUrls;
    }

    public String[] getPatchInfo() {
        return patchInfo;
    }

    public void setPatchInfo(String[] patchInfo) {
        this.patchInfo = patchInfo;
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

    public static RepoMeta fromRepoInfoVo(String productType, RepoInfoVo repoInfoVo) {
        RepoMeta repoMeta = new RepoMeta();
        repoMeta.setId(repoInfoVo.getId());
        repoMeta.setProductType(productType);
        repoMeta.setRepoName(repoInfoVo.getRepoName());
        repoMeta.setBranch(repoInfoVo.getBranch());
        repoMeta.setDownloadLocation(repoInfoVo.getDownloadLocation());
        repoMeta.setSpecDownloadUrl(repoInfoVo.getSpecDownloadUrl());
        repoMeta.setUpstreamDownloadUrls(repoInfoVo.getUpstreamDownloadUrls() == null ? null : repoInfoVo.getUpstreamDownloadUrls().toArray(new String[0]));
        repoMeta.setPatchInfo(repoInfoVo.getPatchInfo() == null ? null : repoInfoVo.getPatchInfo().toArray(new String[0]));
        repoMeta.setPackageNames(repoInfoVo.getPackageNames() == null ? null : repoInfoVo.getPackageNames().toArray(new String[0]));
        HashMap<String, Object> extendedAttr = new HashMap<>();
        extendedAttr.put(SbomRepoConstants.LAST_COMMIT_ID_KEY, repoInfoVo.getLastCommitId());
        repoMeta.setExtendedAttr(extendedAttr);
        return repoMeta;
    }

    @SuppressWarnings("unchecked")
    public List<String> getUpstreamUrls() {
        if (this.extendedAttr == null || !extendedAttr.containsKey(SbomRepoConstants.UPSTREAM_ATTR_KEY)) {
            return new ArrayList<>();
        }
        return (List<String>) extendedAttr.get(SbomRepoConstants.UPSTREAM_ATTR_KEY);
    }
    
}
