package org.opensourceway.sbom.model.echarts;

import java.io.Serializable;
import java.util.Objects;

public class Edge implements Serializable {
    private String sourceID;

    private String targetID;

    private Double size = 1.0;

    public Edge(String sourceID, String targetID) {
        this.sourceID = sourceID;
        this.targetID = targetID;
    }

    public String getSourceID() {
        return sourceID;
    }

    public void setSourceID(String sourceID) {
        this.sourceID = sourceID;
    }

    public String getTargetID() {
        return targetID;
    }

    public void setTargetID(String targetID) {
        this.targetID = targetID;
    }

    public Double getSize() {
        return size;
    }

    public void setSize(Double size) {
        this.size = size;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Edge edge = (Edge) o;
        return Objects.equals(sourceID, edge.sourceID) && Objects.equals(targetID, edge.targetID);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceID, targetID);
    }
}
