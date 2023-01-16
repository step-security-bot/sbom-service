package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;

public class License implements Serializable {
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String expression;

    @JsonCreator
    public License(@JsonInclude(JsonInclude.Include.NON_EMPTY) String expression) {
        this.expression = expression;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }
}
