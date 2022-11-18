package org.opensourceway.sbom.manager.model.vo;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class ProductConfigVo implements Serializable {

    private String name;

    private String label;

    private Map<String, ProductConfigVo> valueToNextConfig = new HashMap<>();

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

    public Map<String, ProductConfigVo> getValueToNextConfig() {
        return valueToNextConfig;
    }

    public void setValueToNextConfig(Map<String, ProductConfigVo> valueToNextConfig) {
        this.valueToNextConfig = valueToNextConfig;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("ProductConfigVo{");
        sb.append("name='").append(name).append('\'');
        sb.append(", label='").append(label).append('\'');
        sb.append(", valueToNextConfig=").append(valueToNextConfig);
        sb.append('}');
        return sb.toString();
    }
}
