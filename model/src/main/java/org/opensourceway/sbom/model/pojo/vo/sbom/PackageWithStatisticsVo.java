package org.opensourceway.sbom.model.pojo.vo.sbom;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;

public class PackageWithStatisticsVo implements Serializable {

    private UUID id;

    private String name;

    private String version;

    private List<LicenseVo> licenses;

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

    public List<LicenseVo> getLicenses() {
        return licenses;
    }

    public void setLicenses(List<LicenseVo> licenses) {
        this.licenses = licenses;
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

}
