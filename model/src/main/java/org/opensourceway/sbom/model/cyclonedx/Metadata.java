package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;
import java.util.List;

public class Metadata implements Serializable {
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String timestamp;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Tool> tools;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Manufacture manufacture;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Component component;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<License> licenses;

    @JsonCreator
    public Metadata(@JsonInclude(JsonInclude.Include.NON_EMPTY) String timestamp,
                    @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Tool> tools,
                    @JsonInclude(JsonInclude.Include.NON_EMPTY) Manufacture manufacture,
                    @JsonInclude(JsonInclude.Include.NON_EMPTY) Component component,
                    @JsonInclude(JsonInclude.Include.NON_EMPTY) List<License> licenses) {
        this.timestamp = timestamp;
        this.tools = tools;
        this.manufacture = manufacture;
        this.component = component;
        this.licenses = licenses;
    }

    public Metadata() {

    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public List<Tool> getTools() {
        return tools;
    }

    public void setTools(List<Tool> tools) {
        this.tools = tools;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public Manufacture getManufacture() {
        return manufacture;
    }

    public void setManufacture(Manufacture manufacture) {
        this.manufacture = manufacture;
    }

    public List<License> getLicenses() {
        return licenses;
    }

    public void setLicenses(List<License> licenses) {
        this.licenses = licenses;
    }
}
