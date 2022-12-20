package org.opensourceway.sbom.model.echarts;

import java.io.Serializable;
import java.util.Objects;

public class Node implements Serializable {
    private String nodeType;

    private String label;

    private Double x;

    private Double y;

    private String id;

    private Double size;

    private String elementId;

    public Node(String id) {
        this.id = id;
    }

    public Node() {
    }

    public String getNodeType() {
        return nodeType;
    }

    public void setNodeType(String nodeType) {
        this.nodeType = nodeType;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Double getX() {
        return x;
    }

    public void setX(Double x) {
        this.x = x;
    }

    public Double getY() {
        return y;
    }

    public void setY(Double y) {
        this.y = y;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Double getSize() {
        return size;
    }

    public void setSize(Double size) {
        this.size = size;
    }

    public String getElementId() {
        return elementId;
    }

    public void setElementId(String elementId) {
        this.elementId = elementId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Node node = (Node) o;
        return Objects.equals(nodeType, node.nodeType) && Objects.equals(label, node.label);
    }

    @Override
    public int hashCode() {
        return Objects.hash(nodeType, label);
    }
}
