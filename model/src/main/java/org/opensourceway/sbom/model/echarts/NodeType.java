package org.opensourceway.sbom.model.echarts;

public enum NodeType {
    VUL("vulnerability"),

    DEP("dependency"),

    PKG("package"),

    TRANSITIVE_DEP("transitiveDep");

    private final String type;

    NodeType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
