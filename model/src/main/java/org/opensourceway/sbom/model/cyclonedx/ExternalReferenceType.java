package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ExternalReferenceType {

    VCS("vcs"),

    ISSUE_TRACKER("issue-tracker"),

    WEBSITE("website"),

    ADVISORIES("advisories"),

    BOM("bom"),

    MAILING_LIST("mailing-list"),

    SOCIAL("social"),

    CHAT("chat"),

    DOCUMENTATION("documentation"),

    SUPPORT("support"),

    DISTRIBUTION("distribution"),

    LICENSE("license"),

    BUILD_META("build-meta"),

    BUILD_SYSTEM("build-system"),

    RELEASE_NOTES("release-notes"),

    OTHER("other"),

    PROVIDE_MANAGER("PROVIDE_MANAGER"),

    EXTERNAL_MANAGER("EXTERNAL_MANAGER");


    private final String type;

    ExternalReferenceType(String type) {
        this.type = type;
    }

    @JsonValue
    public String getType() {
        return type;
    }
}
