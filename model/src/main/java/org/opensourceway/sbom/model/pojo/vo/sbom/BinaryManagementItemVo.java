package org.opensourceway.sbom.model.pojo.vo.sbom;

import org.opensourceway.sbom.model.entity.ExternalPurlRef;

public class BinaryManagementItemVo {
    private String pkgName;

    private String category;

    private String type;

    private PackageUrlVo purl;

    public String getPkgName() {
        return pkgName;
    }

    public void setPkgName(String pkgName) {
        this.pkgName = pkgName;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public PackageUrlVo getPurl() {
        return purl;
    }

    public void setPurl(PackageUrlVo purl) {
        this.purl = purl;
    }

    public static BinaryManagementItemVo fromExternalPurlRef(ExternalPurlRef ref) {
        var vo = new BinaryManagementItemVo();
        vo.setPkgName(ref.getPkg().getName());
        vo.setCategory(ref.getCategory());
        vo.setPurl(ref.getPurl());
        vo.setType(ref.getType());
        return vo;
    }
}
