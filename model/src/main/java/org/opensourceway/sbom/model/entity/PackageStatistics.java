package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.vladmihalcea.hibernate.type.array.ListArrayType;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import java.util.List;
import java.util.UUID;

/**
 * Statistics of a package
 */
@Entity
@Table
@TypeDef(
        name = "list-array",
        typeClass = ListArrayType.class
)
public class PackageStatistics {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Number of dependencies of a package.
     *
     * @see ReferenceCategory#EXTERNAL_MANAGER
     */
    private Long depCount;

    /**
     * Number of modules of a package.
     *
     * @see ReferenceCategory#PROVIDE_MANAGER
     */
    private Long moduleCount;

    /**
     * Number of runtime dependencies of a package.
     */
    private Long runtimeDepCount;

    /**
     * Number of all distinct vulnerabilities of a package.
     */
    private Long vulCount;

    /**
     * Number of all distinct licenses of a package.
     */
    private Long licenseCount;

    /**
     * Number of all distinct critical vulnerabilities of a package.
     * Vulnerability severity classification: <a href="https://nvd.nist.gov/vuln-metrics/cvss">nvd cvss metrics</a>
     */
    private Long criticalVulCount;

    /**
     * Number of all distinct high vulnerabilities of a package.
     */
    private Long highVulCount;

    /**
     * Number of all distinct medium vulnerabilities of a package.
     */
    private Long mediumVulCount;

    /**
     * Number of all distinct low vulnerabilities of a package.
     */
    private Long lowVulCount;

    /**
     * Number of all distinct none vulnerabilities of a package.
     */
    private Long noneVulCount;

    /**
     * Number of all distinct unknown vulnerabilities of a package.
     */
    private Long unknownVulCount;

    /**
     * The severity of the most severe vulnerability affecting the package.
     *
     * @see CvssSeverity
     */
    @Column(columnDefinition = "TEXT")
    private String severity;

    /**
     * Whether all licenses of a package are legal.
     */
    private Boolean isLegalLicense;

    /**
     * A list of all distinct license names of a package.
     */
    @Column(columnDefinition = "TEXT[]")
    @Type(type = "list-array")
    private List<String> licenses;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "package_id", foreignKey = @ForeignKey(name = "product_id_fk"))
    @JsonIgnore
    private Package pkg;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Long getDepCount() {
        return depCount;
    }

    public void setDepCount(Long depCount) {
        this.depCount = depCount;
    }

    public Long getModuleCount() {
        return moduleCount;
    }

    public void setModuleCount(Long moduleCount) {
        this.moduleCount = moduleCount;
    }

    public Long getRuntimeDepCount() {
        return runtimeDepCount;
    }

    public void setRuntimeDepCount(Long runtimeDepCount) {
        this.runtimeDepCount = runtimeDepCount;
    }

    public Long getVulCount() {
        return vulCount;
    }

    public void setVulCount(Long vulCount) {
        this.vulCount = vulCount;
    }

    public Long getLicenseCount() {
        return licenseCount;
    }

    public void setLicenseCount(Long licenseCount) {
        this.licenseCount = licenseCount;
    }

    public Long getCriticalVulCount() {
        return criticalVulCount;
    }

    public void setCriticalVulCount(Long criticalVulCount) {
        this.criticalVulCount = criticalVulCount;
    }

    public Long getHighVulCount() {
        return highVulCount;
    }

    public void setHighVulCount(Long highVulCount) {
        this.highVulCount = highVulCount;
    }

    public Long getMediumVulCount() {
        return mediumVulCount;
    }

    public void setMediumVulCount(Long mediumVulCount) {
        this.mediumVulCount = mediumVulCount;
    }

    public Long getLowVulCount() {
        return lowVulCount;
    }

    public void setLowVulCount(Long lowVulCount) {
        this.lowVulCount = lowVulCount;
    }

    public Long getNoneVulCount() {
        return noneVulCount;
    }

    public void setNoneVulCount(Long noneVulCount) {
        this.noneVulCount = noneVulCount;
    }

    public Long getUnknownVulCount() {
        return unknownVulCount;
    }

    public void setUnknownVulCount(Long unknownVulCount) {
        this.unknownVulCount = unknownVulCount;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Boolean getLegalLicense() {
        return isLegalLicense;
    }

    public void setLegalLicense(Boolean legalLicense) {
        isLegalLicense = legalLicense;
    }

    public List<String> getLicenses() {
        return licenses;
    }

    public void setLicenses(List<String> licenses) {
        this.licenses = licenses;
    }

    public Package getPkg() {
        return pkg;
    }

    public void setPkg(Package pkg) {
        this.pkg = pkg;
    }
}
