package org.opensourceway.sbom.manager.model.vo;

import java.io.Serializable;

public class PackageStatisticsVo implements Serializable {

    private Long criticalVulCount;

    private Long highVulCount;

    private Long mediumVulCount;

    private Long lowVulCount;

    private Long noneVulCount;

    private Long unknownVulCount;

    public Long getCriticalVulCount() {
        return criticalVulCount;
    }

    public void setCriticalVulCount(Long criticalVulCount) {
        this.criticalVulCount = criticalVulCount;
    }

    public Long getHighVulCount() {
        return highVulCount;
    }

    public void setHighVulCount(Long highVulCount) {
        this.highVulCount = highVulCount;
    }

    public Long getMediumVulCount() {
        return mediumVulCount;
    }

    public void setMediumVulCount(Long mediumVulCount) {
        this.mediumVulCount = mediumVulCount;
    }

    public Long getLowVulCount() {
        return lowVulCount;
    }

    public void setLowVulCount(Long lowVulCount) {
        this.lowVulCount = lowVulCount;
    }

    public Long getNoneVulCount() {
        return noneVulCount;
    }

    public void setNoneVulCount(Long noneVulCount) {
        this.noneVulCount = noneVulCount;
    }

    public Long getUnknownVulCount() {
        return unknownVulCount;
    }

    public void setUnknownVulCount(Long unknownVulCount) {
        this.unknownVulCount = unknownVulCount;
    }
}
