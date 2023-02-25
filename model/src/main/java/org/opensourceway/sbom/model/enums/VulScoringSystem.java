package org.opensourceway.sbom.model.enums;

import org.apache.commons.lang3.StringUtils;

public enum VulScoringSystem {
    CVSS_V2,

    CVSS_V3;

    public static VulScoringSystem findVulScoringSystemByName(String scoringSystem) {
        for (VulScoringSystem vulScoringSystem : VulScoringSystem.values()) {
            if (StringUtils.equals(vulScoringSystem.name(), scoringSystem)) {
                return vulScoringSystem;
            }
        }
        throw new RuntimeException("invalid vulnerability scoring system: [%s]".formatted(scoringSystem));
    }
}
