package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;

public class Rating {
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String score;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private VulnerabilitySeverity severity;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private VulnerabilityMethod method;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String vector;

    public Rating(@JsonInclude(JsonInclude.Include.NON_EMPTY) String score,
                  @JsonInclude(JsonInclude.Include.NON_EMPTY) VulnerabilitySeverity severity,
                  @JsonInclude(JsonInclude.Include.NON_EMPTY) VulnerabilityMethod method,
                  @JsonInclude(JsonInclude.Include.NON_EMPTY) String vector) {
        this.score = score;
        this.severity = severity;
        this.method = method;
        this.vector = vector;
    }

    public String getScore() {
        return score;
    }

    public void setScore(String score) {
        this.score = score;
    }

    public VulnerabilitySeverity getSeverity() {
        return severity;
    }

    public void setSeverity(VulnerabilitySeverity severity) {
        this.severity = severity;
    }

    public VulnerabilityMethod getMethod() {
        return method;
    }

    public void setMethod(VulnerabilityMethod method) {
        this.method = method;
    }

    public String getVector() {
        return vector;
    }

    public void setVector(String vector) {
        this.vector = vector;
    }
}
