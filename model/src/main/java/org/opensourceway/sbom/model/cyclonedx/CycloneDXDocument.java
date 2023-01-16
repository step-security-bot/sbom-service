package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.opensourceway.sbom.model.sbom.SbomDocument;

import java.io.Serializable;
import java.util.List;

@JsonClassDescription
public class CycloneDXDocument implements SbomDocument, Serializable {
    public CycloneDXDocument(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    private String bomFormat;

    private String specVersion;

    private Integer version;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String serialNumber;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Metadata metadata;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Component> components;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Dependency> dependencies;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Vulnerability> vulnerabilities;

    @JsonCreator
    public CycloneDXDocument(String bomFormat, String specVersion, Integer version,
                             @JsonInclude(JsonInclude.Include.NON_EMPTY) String serialNumber,
                             @JsonInclude(JsonInclude.Include.NON_EMPTY) Metadata metadata,
                             @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Component> components,
                             @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Dependency> dependencies,
                             @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Vulnerability> vulnerabilities) {
        this.bomFormat = bomFormat;
        this.specVersion = specVersion;
        this.version = version;
        this.serialNumber = serialNumber;
        this.metadata = metadata;
        this.components = components;
        this.dependencies = dependencies;
        this.vulnerabilities = vulnerabilities;
    }

    public String getBomFormat() {
        return bomFormat;
    }

    public void setBomFormat(String bomFormat) {
        this.bomFormat = bomFormat;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public Metadata getMetadata() {
        return metadata;
    }

    public void setMetadata(Metadata metadata) {
        this.metadata = metadata;
    }

    public List<Component> getComponents() {
        return components;
    }

    public void setComponents(List<Component> components) {
        this.components = components;
    }

    public List<Dependency> getDependencies() {
        return dependencies;
    }

    public void setDependencies(List<Dependency> dependencies) {
        this.dependencies = dependencies;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}
