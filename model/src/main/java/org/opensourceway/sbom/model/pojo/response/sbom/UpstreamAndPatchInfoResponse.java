package org.opensourceway.sbom.model.pojo.response.sbom;

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class UpstreamAndPatchInfoResponse {

    private List<Map<String, String>> upstreamList = new ArrayList<>();

    private List<Map<String, String>> patchList = new ArrayList<>();

    public List<Map<String, String>> getUpstreamList() {
        return upstreamList;
    }

    public void setUpstreamList(List<Map<String, String>> upstreamList) {
        this.upstreamList = upstreamList;
    }

    public List<Map<String, String>> getPatchList() {
        return patchList;
    }

    public void setPatchList(List<Map<String, String>> patchList) {
        this.patchList = patchList;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
