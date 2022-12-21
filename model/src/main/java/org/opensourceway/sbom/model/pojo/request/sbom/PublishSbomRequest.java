package org.opensourceway.sbom.model.pojo.request.sbom;

import java.io.Serializable;

public class PublishSbomRequest implements Serializable {

    private String productName;

    private String sbomContent;

    private String sbomContentType;

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getSbomContent() {
        return sbomContent;
    }

    public void setSbomContent(String sbomContent) {
        this.sbomContent = sbomContent;
    }

    public String getSbomContentType() {
        return sbomContentType;
    }

    public void setSbomContentType(String sbomContentType) {
        this.sbomContentType = sbomContentType;
    }

    @Override
    public String toString() {
        return "PublishSbomRequest{" +
                "productName='" + productName + '\'' +
                ", sbomContentType='" + sbomContentType + '\'' +
                '}';
    }
}
