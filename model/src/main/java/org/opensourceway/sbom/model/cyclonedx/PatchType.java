package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonValue;

public enum PatchType {
    UNOFFICIAL("unofficial"),

    MONKEY("monkey"),

    BACKPORT("backport"),

    CHERRY_PICK("cherry-pick");

    private final String type;

    PatchType(String type) {
        this.type = type;
    }

    @JsonValue
    public String getType() {
        return type;
    }
}
