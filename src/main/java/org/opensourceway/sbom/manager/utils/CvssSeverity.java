package org.opensourceway.sbom.manager.utils;

import org.opensourceway.sbom.manager.model.VulScoringSystem;

import java.util.Objects;

public enum CvssSeverity {
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
        if (VulScoringSystem.CVSS2.equals(vulScoringSystem)) {
            for (CvssSeverity severity : CvssSeverity.values()) {
                if (Objects.isNull(severity.getCvss2LowerBound())) {
                    continue;
                }
                if (severity.getCvss2LowerBound() <= score && score <= severity.getCvss2UpperBound()) {
                    return severity;
                }
            }
        } else if (VulScoringSystem.CVSS3.equals(vulScoringSystem)) {
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
}
