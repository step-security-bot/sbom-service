package org.opensourceway.sbom.manager.dao.spec;

import org.opensourceway.sbom.manager.model.spdx.ReferenceType;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.springframework.data.util.Pair;

import java.util.Map;
import java.util.UUID;

public class ExternalPurlRefCondition {

    private String productName;

    private UUID sbomId;

    private String binaryType;

    private String refType;

    private String sortField;

    private Map<String, Pair<String, Boolean>> purlComponents;

    private String type;

    private Boolean isTypeExactly;

    private String namespace;

    private Boolean isNamespaceExactly;

    private String name;

    private Boolean isNameExactly;

    private String version;

    private Boolean isVersionExactly;

    private String startVersion;

    private String endVersion;

    private ExternalPurlRefCondition(Builder builder) {
        this.productName = builder.productName;
        this.sbomId = builder.sbomId;
        this.binaryType = builder.binaryType;
        this.refType = builder.refType;
        this.sortField = builder.sortField;

        this.startVersion = builder.startVersion;
        this.endVersion = builder.endVersion;

        PackageUrlVo purl = new PackageUrlVo(builder.type, builder.namespace, builder.name, builder.version);
        this.purlComponents = PurlUtil.generatePurlQueryConditionMap(purl, builder.startVersion, builder.endVersion);

        if (this.purlComponents.containsKey("type")) {
            this.type = this.purlComponents.get("type").getFirst();
            this.isTypeExactly = this.purlComponents.get("type").getSecond();
        }
        if (this.purlComponents.containsKey("namespace")) {
            this.namespace = this.purlComponents.get("namespace").getFirst();
            this.isNamespaceExactly = this.purlComponents.get("namespace").getSecond();
        }
        if (this.purlComponents.containsKey("name")) {
            this.name = this.purlComponents.get("name").getFirst();
            this.isNameExactly = this.purlComponents.get("name").getSecond();
        }
        if (this.purlComponents.containsKey("version")) {
            this.version = this.purlComponents.get("version").getFirst();
            this.isVersionExactly = this.purlComponents.get("version").getSecond();
        }
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public UUID getSbomId() {
        return sbomId;
    }

    public void setSbomId(UUID sbomId) {
        this.sbomId = sbomId;
    }

    public String getBinaryType() {
        return binaryType;
    }

    public void setBinaryType(String binaryType) {
        this.binaryType = binaryType;
    }

    public String getRefType() {
        return refType;
    }

    public void setRefType(String refType) {
        this.refType = refType;
    }

    public String getSortField() {
        return sortField;
    }

    public void setSortField(String sortField) {
        this.sortField = sortField;
    }

    public Map<String, Pair<String, Boolean>> getPurlComponents() {
        return purlComponents;
    }

    public void setPurlComponents(Map<String, Pair<String, Boolean>> purlComponents) {
        this.purlComponents = purlComponents;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Boolean getTypeExactly() {
        return isTypeExactly;
    }

    public void setTypeExactly(Boolean typeExactly) {
        isTypeExactly = typeExactly;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public Boolean getNamespaceExactly() {
        return isNamespaceExactly;
    }

    public void setNamespaceExactly(Boolean namespaceExactly) {
        isNamespaceExactly = namespaceExactly;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean getNameExactly() {
        return isNameExactly;
    }

    public void setNameExactly(Boolean nameExactly) {
        isNameExactly = nameExactly;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Boolean getVersionExactly() {
        return isVersionExactly;
    }

    public void setVersionExactly(Boolean versionExactly) {
        isVersionExactly = versionExactly;
    }

    public String getStartVersion() {
        return startVersion;
    }

    public void setStartVersion(String startVersion) {
        this.startVersion = startVersion;
    }

    public String getEndVersion() {
        return endVersion;
    }

    public void setEndVersion(String endVersion) {
        this.endVersion = endVersion;
    }

    public static final class Builder {

        private String productName;

        private UUID sbomId;

        private String binaryType;

        private String refType = ReferenceType.PURL.getType();

        private String sortField;

        private String type;

        private String namespace;

        private String name;

        private String version;

        private String startVersion;

        private String endVersion;

        public Builder() {
        }

        public static Builder newBuilder() {
            return new Builder();
        }

        public Builder productName(String val) {
            productName = val;
            return this;
        }

        public Builder sbomId(UUID val) {
            sbomId = val;
            return this;
        }

        public Builder binaryType(String val) {
            binaryType = val;
            return this;
        }

        public Builder refType(String val) {
            refType = val;
            return this;
        }

        public Builder sortField(String val) {
            sortField = val;
            return this;
        }

        public Builder type(String val) {
            type = val;
            return this;
        }

        public Builder namespace(String val) {
            namespace = val;
            return this;
        }

        public Builder name(String val) {
            name = val;
            return this;
        }

        public Builder version(String val) {
            version = val;
            return this;
        }

        public Builder startVersion(String val) {
            startVersion = val;
            return this;
        }

        public Builder endVersion(String val) {
            endVersion = val;
            return this;
        }

        public ExternalPurlRefCondition build() {
            return new ExternalPurlRefCondition(this);
        }
    }

}