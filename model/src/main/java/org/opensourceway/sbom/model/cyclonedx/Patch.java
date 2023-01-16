package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;

public class Patch {
    PatchType type;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    PatchDiff diff;

    public Patch(PatchType type, PatchDiff diff) {
        this.type = type;
        this.diff = diff;
    }

    public PatchType getType() {
        return type;
    }

    public void setType(PatchType type) {
        this.type = type;
    }

    public PatchDiff getDiff() {
        return diff;
    }

    public void setDiff(PatchDiff diff) {
        this.diff = diff;
    }
}
