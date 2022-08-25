package org.openeuler.sbom.clients.license.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RepoLegal implements Serializable {
    private String pass;

    @JsonProperty("result_code")
    private String resultCode;

    private String notice;

    @JsonProperty("is_legal")
    private IsLegal isLegal;

    private List<String> copyright;

    public String getPass() { return pass;}

    public void setPass(String pass) {
        this.pass = pass;
    }

    public String getNotice() {
        return notice;
    }

    public void setNotice(String notice) {
        this.notice = notice;
    }

    public IsLegal getIsLegal() {
        return isLegal;
    }

    public void setIsLegal(IsLegal isLegal) {
        this.isLegal = isLegal;
    }

    public String getResultCode() {
        return resultCode;
    }

    public void setResultCode(String resultCode) {
        this.resultCode = resultCode;
    }

    public List<String> getCopyright() {
        return copyright;
    }

    public void setCopyright(List<String> copyright) {
        this.copyright = copyright;
    }
}
