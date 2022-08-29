package org.opensourceway.sbom.clients.license.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class Detail implements Serializable {

    @JsonProperty("is_standard")
    private DetailInfo isStandard;

    @JsonProperty("is_white")
    private DetailInfo isWhite;

    @JsonProperty("is_review")
    private DetailInfo isReview;

    public DetailInfo getIsStandard() {
        return isStandard;
    }

    public void setIsStandard(DetailInfo isStandard) {
        this.isStandard = isStandard;
    }

    public DetailInfo getIsWhite() {
        return isWhite;
    }

    public void setIsWhite(DetailInfo isWhite) {
        this.isWhite = isWhite;
    }

    public DetailInfo getIsReview() {
        return isReview;
    }

    public void setIsReview(DetailInfo isReview) {
        this.isReview = isReview;
    }
}
