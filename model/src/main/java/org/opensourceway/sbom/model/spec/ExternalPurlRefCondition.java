package org.opensourceway.sbom.model.spec;

import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.springframework.data.util.Pair;
import org.springframework.util.CollectionUtils;

import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

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
        this.purlComponents = generatePurlQueryConditionMap(purl, builder.startVersion, builder.endVersion);

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

    public Boolean isTypeExactly() {
        return isTypeExactly;
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

    public Boolean isNamespaceExactly() {
        return isNamespaceExactly;
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

    public Boolean isNameExactly() {
        return isNameExactly;
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

    public Boolean isVersionExactly() {
        return isVersionExactly;
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

    public static Map<String, Pair<String, Boolean>> generatePurlQueryConditionMap(PackageUrlVo purl, String startVersion, String endVersion) {
        String type = StringUtils.lowerCase(purl.getType());
        switch (type) {
            case "maven":
                return generateMavenPurlQueryConditionMap(purl.getNamespace(), purl.getName(), purl.getVersion(), startVersion, endVersion);
            case "rpm":
                return generateRpmPurlQueryConditionMap(purl.getName(), purl.getVersion(), startVersion, endVersion);
            case "pypi":
            case "github":
            case "gitlab":
            case "gitee":
            case PackageURL.StandardTypes.GENERIC:
                return generateNoNamespacePurlQueryConditionMap(type, purl.getName(), purl.getVersion(), startVersion, endVersion);
            // TODO 后续追加其他包管理的支持
        }

        throw new RuntimeException("purl query condition not support type: " + type);
    }

    /**
     * 根据Maven PURL参数拼装查询参数:
     * <p>
     * 1. name必须有值
     * <p>
     * 2. name仅在(version/startVersion/endVersion)任一有值且namespace有值场景下才进行精确查询，否则使用模糊匹配
     * <p>
     * 3. version和namespace若有值进行精确查询
     */
    private static Map<String, Pair<String, Boolean>> generateMavenPurlQueryConditionMap(String namespace, String name, String version,
                                                                                         String startVersion, String endVersion) {
        if (StringUtils.isEmpty(name)) {
            throw new RuntimeException(("maven purl query condition params is error, namespace: %s, name: %s, version: %s, " +
                    "startVersion: %s, endVersion: %s").formatted(namespace, name, version, startVersion, endVersion));
        }
        Map<String, Pair<String, Boolean>> purlComponents = CollectionUtils.newHashMap(0);
        purlComponents.put("type", Pair.of(SbomConstants.PURL_MAVEN_TYPE_VALUE, true));

        if (StringUtils.isNotEmpty(version)) {
            purlComponents.put("version", Pair.of(version, true));
        }
        if (StringUtils.isNotEmpty(namespace)) {
            purlComponents.put("namespace", Pair.of(namespace, true));
        }

        if (StringUtils.isNotEmpty(namespace) && (Stream.of(version, startVersion, endVersion).anyMatch(StringUtils::isNotEmpty))) {
            purlComponents.put("name", Pair.of(name, true));
        } else {
            purlComponents.put("name", Pair.of(name, false));
        }

        return purlComponents;
    }

    /**
     * RPM的version比较特殊，使用epoch:version-release格式，转成PURL之后，PURL中的version为version-release；epoch放在PURL的qualifiers中，<a href="https://github.com/package-url/purl-spec/issues/69">https://github.com/package-url/purl-spec/issues/69</a>
     * <p>
     * 根据RPM PURL(name+version)参数拼装查询参数:
     * <p>
     * 1. name必须有值
     * <p>
     * 2. name在(version/startVersion/endVersion)任一有值场景下进行精确查询，否则使用模糊匹配
     * <p>
     * 3. version若有值进行模糊匹配(页面仅需要传值epoch:version-release中的version部分)
     */
    private static Map<String, Pair<String, Boolean>> generateRpmPurlQueryConditionMap(String name, String version,
                                                                                       String startVersion, String endVersion) {
        if (StringUtils.isEmpty(name)) {
            throw new RuntimeException(("rpm purl query condition params is error, name: %s, version: %s, " +
                    "startVersion: %s, endVersion: %s").formatted(name, version, startVersion, endVersion));
        }
        Map<String, Pair<String, Boolean>> purlComponents = CollectionUtils.newHashMap(0);
        purlComponents.put("type", Pair.of(SbomConstants.PURL_RPM_TYPE_VALUE, true));

        if (StringUtils.isNotEmpty(version)) {
            purlComponents.put("version", Pair.of(version, false));
            purlComponents.put("name", Pair.of(name, true));
        } else if (Stream.of(startVersion, endVersion).anyMatch(StringUtils::isNotEmpty)) {
            purlComponents.put("name", Pair.of(name, true));
        } else {
            purlComponents.put("name", Pair.of(name, false));
        }

        return purlComponents;
    }

    /**
     * 根据PURL(name+version)参数拼装查询参数:
     * <p>
     * 1. name必须有值
     * <p>
     * 2. name在(version/startVersion/endVersion)任一有值场景下进行精确查询，否则使用模糊匹配
     * <p>
     * 3. version若有值进行精确查询
     */
    private static Map<String, Pair<String, Boolean>> generateNoNamespacePurlQueryConditionMap(String type, String name, String version,
                                                                                               String startVersion, String endVersion) {
        if (StringUtils.isEmpty(name)) {
            throw new RuntimeException(("%s purl query condition params is error, name: %s, version: %s, " +
                    "startVersion: %s, endVersion: %s").formatted(type, name, version, startVersion, endVersion));
        }
        Map<String, Pair<String, Boolean>> purlComponents = CollectionUtils.newHashMap(0);
        purlComponents.put("type", Pair.of(type, true));

        if (StringUtils.isNotEmpty(version)) {
            purlComponents.put("version", Pair.of(version, true));
            purlComponents.put("name", Pair.of(name, true));
        } else if (Stream.of(startVersion, endVersion).anyMatch(StringUtils::isNotEmpty)) {
            purlComponents.put("name", Pair.of(name, true));
        } else {
            purlComponents.put("name", Pair.of(name, false));
        }

        return purlComponents;
    }

}