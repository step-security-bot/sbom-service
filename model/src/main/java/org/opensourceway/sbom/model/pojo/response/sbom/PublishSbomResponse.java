package org.opensourceway.sbom.model.pojo.response.sbom;

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.UUID;

public class PublishSbomResponse {

    private Boolean success;

    private String errorInfo;

    private UUID taskId;

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public String getErrorInfo() {
        return errorInfo;
    }

    public void setErrorInfo(String errorInfo) {
        this.errorInfo = errorInfo;
    }

    public UUID getTaskId() {
        return taskId;
    }

    public void setTaskId(UUID taskId) {
        this.taskId = taskId;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
