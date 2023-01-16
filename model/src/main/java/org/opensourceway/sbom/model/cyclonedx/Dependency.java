package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

public class Dependency {
    private String ref;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<String> dependsOn;

    public String getRef() {
        return ref;
    }

    public void setRef(String ref) {
        this.ref = ref;
    }

    public List<String> getDependsOn() {
        return dependsOn;
    }

    public void setDependsOn(List<String> dependsOn) {
        this.dependsOn = dependsOn;
    }
}
