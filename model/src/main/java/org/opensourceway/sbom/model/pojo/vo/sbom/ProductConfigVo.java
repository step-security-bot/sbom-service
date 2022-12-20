package org.opensourceway.sbom.model.pojo.vo.sbom;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class ProductConfigVo implements Serializable {

    private String name;

    private String label;

    private String valueLabel;

    private Map<String, ProductConfigVo> valueToNextConfig = new HashMap<>();

    public ProductConfigVo() {
    }

    public ProductConfigVo(String valueLabel) {
        this.valueLabel = valueLabel;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getValueLabel() {
        return valueLabel;
    }

    public void setValueLabel(String valueLabel) {
        this.valueLabel = valueLabel;
    }

    public Map<String, ProductConfigVo> getValueToNextConfig() {
        return valueToNextConfig;
    }

    public void setValueToNextConfig(Map<String, ProductConfigVo> valueToNextConfig) {
        this.valueToNextConfig = valueToNextConfig;
    }

    @Override
    public String toString() {
        return "ProductConfigVo{" +
                "name='" + name + '\'' +
                ", label='" + label + '\'' +
                ", valueLabel='" + valueLabel + '\'' +
                ", valueToNextConfig=" + valueToNextConfig +
                '}';
    }
}
