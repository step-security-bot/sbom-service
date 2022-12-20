package org.opensourceway.sbom.model.pojo.request.sbom;

import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.enums.SbomSpecification;

import java.io.Serializable;

public class PublishSbomRequest implements Serializable {

    private String productName;

    private String spec = SbomSpecification.SPDX_2_2.getSpecification();

    private String specVersion = SbomSpecification.SPDX_2_2.getVersion();

    private String format = SbomFormat.JSON.getFileExtName();

    private String sbomContent;

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getSpec() {
        return spec;
    }

    public void setSpec(String spec) {
        this.spec = spec;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getSbomContent() {
        return sbomContent;
    }

    public void setSbomContent(String sbomContent) {
        this.sbomContent = sbomContent;
    }

    @Override
    public String toString() {
        return "PublishSbomRequest{" +
                "productName='" + productName + '\'' +
                ", spec='" + spec + '\'' +
                ", specVersion='" + specVersion + '\'' +
                ", format='" + format + '\'' +
                '}';
    }
}
