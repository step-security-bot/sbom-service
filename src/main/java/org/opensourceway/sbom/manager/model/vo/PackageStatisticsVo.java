package org.opensourceway.sbom.manager.model.vo;

import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.VulSource;
import org.opensourceway.sbom.manager.model.Vulnerability;
import org.opensourceway.sbom.manager.utils.CvssSeverity;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
            Map<CvssSeverity, Long> vulSeverityVulCountMap = dedupVulnerability(pkg.getExternalVulRefs().stream()
                    .map(ExternalVulRef::getVulnerability)
                    .distinct())
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

    private static Stream<Vulnerability> dedupVulnerability(Stream<Vulnerability> vulnerabilityStream) {
        var sourceToVul = vulnerabilityStream.collect(Collectors.groupingBy(Vulnerability::getSource, Collectors.toList()));
        var ossIndexVuls = sourceToVul.getOrDefault(VulSource.OSS_INDEX.name(), new ArrayList<>());
        var cveManagerVuls = sourceToVul.getOrDefault(VulSource.CVE_MANAGER.name(), new ArrayList<>());
        var ossIndexVulIds = ossIndexVuls.stream().map(Vulnerability::getVulId).toList();
        var cveManagerDupVuls = cveManagerVuls.stream()
                .filter(vul -> ossIndexVulIds.contains(vul.getVulId()))
                .toList();
        ossIndexVuls.addAll(cveManagerVuls);
        ossIndexVuls.removeAll(cveManagerDupVuls);
        return ossIndexVuls.stream();

    }
}
