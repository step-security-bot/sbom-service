package org.opensourceway.sbom.model.pojo.vo.sbom;

import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.enums.CvssSeverity;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
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
        var statistics = pkg.getPackageStatistics();
        if (Objects.nonNull(statistics)) {
            vo.setCriticalVulCount(statistics.getCriticalVulCount());
            vo.setHighVulCount(statistics.getHighVulCount());
            vo.setMediumVulCount(statistics.getMediumVulCount());
            vo.setLowVulCount(statistics.getLowVulCount());
            vo.setNoneVulCount(statistics.getNoneVulCount());
            vo.setUnknownVulCount(statistics.getUnknownVulCount());
        } else {
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
        }
        return vo;
    }

}
