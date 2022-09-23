package org.opensourceway.sbom.manager.model.vo;

import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.utils.CvssSeverity;

import java.io.Serializable;
import java.util.Map;
import java.util.stream.Collectors;

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

    public static PackageStatisticsVo fromPackage(Package pkg) {
        var vo = new PackageStatisticsVo();
        Map<CvssSeverity, Long> vulSeverityVulCountMap = pkg.getExternalVulRefs().stream()
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .collect(Collectors.groupingBy(CvssSeverity::calculateVulCvssSeverity, Collectors.counting()));
        vo.setCriticalVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.CRITICAL, 0L));
        vo.setHighVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.HIGH, 0L));
        vo.setMediumVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.MEDIUM, 0L));
        vo.setLowVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.LOW, 0L));
        vo.setNoneVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.NONE, 0L));
        vo.setUnknownVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.UNKNOWN, 0L));
        return vo;
    }
}
