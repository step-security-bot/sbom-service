package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

public class ExternalReference {

    private String url;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String comment;

    private ExternalReferenceType type;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<Hash> hashes;

    public ExternalReference(String url, @JsonInclude(JsonInclude.Include.NON_EMPTY) String comment, ExternalReferenceType type, @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Hash> hashes) {
        this.url = url;
        this.comment = comment;
        this.type = type;
        this.hashes = hashes;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public ExternalReferenceType getType() {
        return type;
    }

    public void setType(ExternalReferenceType type) {
        this.type = type;
    }

    public List<Hash> getHashes() {
        return hashes;
    }

    public void setHashes(List<Hash> hashes) {
        this.hashes = hashes;
    }
}
