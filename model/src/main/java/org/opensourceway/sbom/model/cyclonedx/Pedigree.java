package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

public class Pedigree {
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Patch> patches;

    public List<Patch> getPatches() {
        return patches;
    }

    @JsonCreator
    public Pedigree(List<Patch> patches) {
        this.patches = patches;
    }

    public void setPatches(List<Patch> patches) {
        this.patches = patches;
    }
}
