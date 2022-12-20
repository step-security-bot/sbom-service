package org.opensourceway.sbom.model.pojo.vo.sbom;

import org.opensourceway.sbom.model.entity.ProductStatistics;

import java.io.Serializable;

public class VulCountVo implements Serializable {

    private Long timestamp;

    private Long criticalVulCount;

    private Long highVulCount;

    private Long mediumVulCount;

    private Long lowVulCount;

    private Long noneVulCount;

    private Long unknownVulCount;

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

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

    public static VulCountVo fromProductStatistics(ProductStatistics productStatistics) {
        VulCountVo vo = new VulCountVo();
        vo.setTimestamp(productStatistics.getCreateTime().getTime());
        vo.setCriticalVulCount(productStatistics.getCriticalVulCount());
        vo.setHighVulCount(productStatistics.getHighVulCount());
        vo.setMediumVulCount(productStatistics.getMediumVulCount());
        vo.setLowVulCount(productStatistics.getLowVulCount());
        vo.setNoneVulCount(productStatistics.getNoneVulCount());
        vo.setUnknownVulCount(productStatistics.getUnknownVulCount());
        return vo;
    }
}
