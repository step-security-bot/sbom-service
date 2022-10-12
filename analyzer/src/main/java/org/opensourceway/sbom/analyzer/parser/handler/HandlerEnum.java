package org.opensourceway.sbom.analyzer.parser.handler;

public enum HandlerEnum {
    GIT_SUBMODULE("git_submodule"),

    GIT_CLONE("git_clone");

    private final String tag;

    HandlerEnum(String tag) {
        this.tag = tag;
    }

    public String getTag() {
        return this.tag;
    }
}
