package org.opensourceway.sbom.model.enums;

import java.util.List;
import java.util.Objects;

public enum VulStatus {
    NOT_ANALYZED(1),

    NORMAL_CLOSED(2),

    NOT_FIXED(3),

    FIXED(4),

    PUBLISHED(5),

    ABNORMAL_CLOSED(6);

    private final Integer status;

    VulStatus(Integer status) {
        this.status = status;
    }

    public Integer getStatus() {
        return status;
    }

    public static final List<VulStatus> activeVulStatus = List.of(NOT_ANALYZED, NOT_FIXED, ABNORMAL_CLOSED);

    public static String findVulStatusByStatus(Integer status) {
        for (VulStatus vulStatus : VulStatus.values()) {
            if (Objects.equals(vulStatus.getStatus(), status)) {
                return vulStatus.name();
            }
        }
        return null;
    }
}
