package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Hash {

    @JsonProperty("alg")
    private Algorithm algorithm;

    private String content;

    public Hash(Algorithm algorithm, String content) {
        this.algorithm = algorithm;
        this.content = content;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}
