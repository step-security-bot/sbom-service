package org.opensourceway.sbom.model.enums;

import java.util.List;

/**
 * cve-manager issue status
 */
public enum IssueStatus {
    TODO(1),

    IN_PROGRESS(2),

    FINISHED(3),

    REJECTED(4),

    HANG_UP(5),

    DELETED(6);

    private final Integer status;

    IssueStatus(Integer status) {
        this.status = status;
    }

    public Integer getStatus() {
        return status;
    }

    public static final List<IssueStatus> activeIssueStatus = List.of(TODO, IN_PROGRESS, HANG_UP);
}
