package org.openeuler.sbom.manager.model;

import org.apache.commons.lang3.StringUtils;

public enum VulRefSource {
    NVD("nvd.nist.gov"),

    OSS_INDEX("ossindex.sonatype.org"),

    GITHUB("github.com");

    final String host;
    VulRefSource(String host) {
        this.host = host;
    }

    public static VulRefSource findVulRefSourceByHost(String host) {
        if (StringUtils.isEmpty(host)) {
            return null;
        }
        for (VulRefSource source : VulRefSource.values()) {
            if (host.contains(source.host)) {
                return source;
            }
        }
        return null;
    }
}
