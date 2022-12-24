package org.opensourceway.sbom.model.pojo.request.sbom;

import java.io.Serializable;
import java.util.Map;

public class AddProductRequest implements Serializable {
    private String productType;

    private String productName;

    private Map<String, ConfigValueLabel> attribute;

    public String getProductType() {
        return productType;
    }

    public void setProductType(String productType) {
        this.productType = productType;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public Map<String, ConfigValueLabel> getAttribute() {
        return attribute;
    }

    public void setAttribute(Map<String, ConfigValueLabel> attribute) {
        this.attribute = attribute;
    }

    @Override
    public String toString() {
        return "AddProductRequest{" +
                "productType='" + productType + '\'' +
                ", name='" + productName + '\'' +
                ", attribute=" + attribute +
                '}';
    }

    public static class ConfigValueLabel implements Serializable {
        private String value;

        private String label;

        public ConfigValueLabel(String value, String label) {
            this.value = value;
            this.label = label;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return "ConfigValueLabel{" +
                    "value='" + value + '\'' +
                    ", label='" + label + '\'' +
                    '}';
        }
    }
}
