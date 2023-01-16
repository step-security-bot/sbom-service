package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ComponentType {
    APPLICATION("application"),

    FRAMEWORK("framework"),

    LIBRARY("library"),

    CONTAINER("container"),

    OPERATING_SYSTEM("operating-system"),

    DEVICE("device"),

    FIRMWARE("firmware"),

    FILE("file");

    private final String type;

    ComponentType(String type) {
        this.type = type;
    }

    @JsonValue
    public String getType() {
        return type;
    }
}
