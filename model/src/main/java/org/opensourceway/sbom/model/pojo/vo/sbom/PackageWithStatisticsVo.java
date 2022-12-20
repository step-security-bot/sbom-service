package org.opensourceway.sbom.model.pojo.vo.sbom;

import org.opensourceway.sbom.model.entity.Package;

import java.io.Serializable;
import java.util.UUID;

public class PackageWithStatisticsVo implements Serializable {

    private UUID id;

    private String name;

    private String version;

    private String licenseConcluded;

    private String copyright;

    private String supplier;

    private PackageStatisticsVo statistics;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getLicenseConcluded() {
        return licenseConcluded;
    }

    public void setLicenseConcluded(String licenseConcluded) {
        this.licenseConcluded = licenseConcluded;
    }

    public String getCopyright() {
        return copyright;
    }

    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    public String getSupplier() {
        return supplier;
    }

    public void setSupplier(String supplier) {
        this.supplier = supplier;
    }

    public PackageStatisticsVo getStatistics() {
        return statistics;
    }

    public void setStatistics(PackageStatisticsVo statistics) {
        this.statistics = statistics;
    }

    public static PackageWithStatisticsVo fromPackage(Package pkg) {
        var vo = new PackageWithStatisticsVo();
        vo.setId(pkg.getId());
        vo.setName(pkg.getName());
        vo.setVersion(pkg.getVersion());
        vo.setLicenseConcluded(pkg.getLicenseConcluded());
        vo.setCopyright(pkg.getCopyright());
        vo.setSupplier(pkg.getSupplier());
        vo.setStatistics(PackageStatisticsVo.fromPackage(pkg));
        return vo;
    }
}
