package org.opensourceway.sbom.model.enums;

import org.apache.commons.lang3.StringUtils;

public enum VcsEnum {
    GITHUB("github.com"),
    GITEE("gitee.com"),
    GITLAB("gitlab.com");

    private final String vcsHost;

    VcsEnum(String vcsHost) {
        this.vcsHost = vcsHost;
    }

    public String getVcsHost() {
        return this.vcsHost;
    }

    public static VcsEnum findVcsEnumByHost(String vcsHost) {
        if (StringUtils.isEmpty(vcsHost)) {
            return null;
        }
        for (VcsEnum vcsEnum : VcsEnum.values()) {
            if (StringUtils.equals(vcsEnum.vcsHost, vcsHost)) {
                return vcsEnum;
            }
        }
        return null;
    }
}
