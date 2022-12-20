package org.opensourceway.sbom.model.pojo.response.sbom;

import org.apache.commons.lang3.builder.ToStringBuilder;

public class PublishResultResponse {
    public PublishResultResponse() {
    }

    public PublishResultResponse(Boolean success, Boolean finish, String errorInfo, String sbomRef) {
        this.success = success;
        this.finish = finish;
        this.errorInfo = errorInfo;
        this.sbomRef = sbomRef;
    }

    private Boolean success;

    private Boolean finish;

    private String errorInfo;

    private String sbomRef;

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public Boolean getFinish() {
        return finish;
    }

    public void setFinish(Boolean finish) {
        this.finish = finish;
    }

    public String getErrorInfo() {
        return errorInfo;
    }

    public void setErrorInfo(String errorInfo) {
        this.errorInfo = errorInfo;
    }

    public String getSbomRef() {
        return sbomRef;
    }

    public void setSbomRef(String sbomRef) {
        this.sbomRef = sbomRef;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
