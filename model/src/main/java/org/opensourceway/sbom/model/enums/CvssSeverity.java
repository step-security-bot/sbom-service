package org.opensourceway.sbom.model.enums;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.model.entity.VulScore;
import org.opensourceway.sbom.model.entity.Vulnerability;

import java.util.List;
import java.util.Objects;

public enum CvssSeverity {
    NA(-2, null, null, null, null),

    UNKNOWN(-1, null, null, null, null),

    NONE(0, null, null, 0.0, 0.0),

    LOW(1, 0.0, 3.9, 0.1, 3.9),

    MEDIUM(2, 4.0, 6.9, 4.0, 6.9),

    HIGH(3, 7.0, 10.0, 7.0, 8.9),

    CRITICAL(4, null, null, 9.0, 10.0);

    private final Integer severity;

    private final Double cvss2LowerBound;

    private final Double cvss2UpperBound;

    private final Double cvss3LowerBound;

    private final Double cvss3UpperBound;

    CvssSeverity(Integer severity, Double cvss2LowerBound, Double cvss2UpperBound, Double cvss3LowerBound, Double cvss3UpperBound) {
        this.severity = severity;
        this.cvss2LowerBound = cvss2LowerBound;
        this.cvss2UpperBound = cvss2UpperBound;
        this.cvss3LowerBound = cvss3LowerBound;
        this.cvss3UpperBound = cvss3UpperBound;
    }

    public Integer getSeverity() {
        return severity;
    }

    public Double getCvss2LowerBound() {
        return cvss2LowerBound;
    }

    public Double getCvss2UpperBound() {
        return cvss2UpperBound;
    }

    public Double getCvss3LowerBound() {
        return cvss3LowerBound;
    }

    public Double getCvss3UpperBound() {
        return cvss3UpperBound;
    }

    public static CvssSeverity calculateCvssSeverity(VulScoringSystem vulScoringSystem, Double score) {
        if (VulScoringSystem.CVSS_V2.equals(vulScoringSystem)) {
            for (CvssSeverity severity : CvssSeverity.values()) {
                if (Objects.isNull(severity.getCvss2LowerBound())) {
                    continue;
                }
                if (severity.getCvss2LowerBound() <= score && score <= severity.getCvss2UpperBound()) {
                    return severity;
                }
            }
        } else if (VulScoringSystem.CVSS_V3.equals(vulScoringSystem)) {
            for (CvssSeverity severity : CvssSeverity.values()) {
                if (Objects.isNull(severity.getCvss3LowerBound())) {
                    continue;
                }
                if (severity.getCvss3LowerBound() <= score && score <= severity.getCvss3UpperBound()) {
                    return severity;
                }
            }
        } else {
            throw new RuntimeException("invalid vulnerability scoring system: [%s]".formatted(vulScoringSystem));
        }
        throw new RuntimeException("score [%s] doesn't match vulnerability scoring system: [%s]".formatted(score, vulScoringSystem));
    }

    public static CvssSeverity calculateVulCvssSeverity(Vulnerability vul) {
        CvssSeverity cvssSeverity = CvssSeverity.UNKNOWN;
        List<VulScore> scores = vul.getVulScores();

        if (scores.size() == 1) {
            cvssSeverity = CvssSeverity.valueOf(scores.get(0).getSeverity());
        } else if (scores.size() > 1) {
            VulScore cvss3 = scores.stream()
                    .filter(score -> StringUtils.equals(score.getScoringSystem(), VulScoringSystem.CVSS_V3.name()))
                    .findFirst()
                    .orElse(null);
            VulScore cvss2 = scores.stream()
                    .filter(score -> StringUtils.equals(score.getScoringSystem(), VulScoringSystem.CVSS_V2.name()))
                    .findFirst()
                    .orElse(null);

            if (Objects.nonNull(cvss3)) {
                cvssSeverity = CvssSeverity.valueOf(cvss3.getSeverity());
            } else if (Objects.nonNull(cvss2)) {
                cvssSeverity = CvssSeverity.valueOf(cvss2.getSeverity());
            }
        }

        return cvssSeverity;
    }
}
