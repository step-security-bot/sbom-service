package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.sql.Timestamp;
import java.util.Map;
import java.util.UUID;

/**
 * Statistics of a product
 */
@Entity
@TypeDefs({
        @TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
})
@Table
public class ProductStatistics {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @Column(columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private Timestamp createTime;

    /**
     * Number of packages of a product.
     * @see ReferenceCategory#PACKAGE_MANAGER
     */
    private Long packageCount;

    /**
     * Number of dependencies of a product.
     * @see ReferenceCategory#EXTERNAL_MANAGER
     */
    private Long depCount;

    /**
     * Number of modules of a product.
     * @see ReferenceCategory#PROVIDE_MANAGER
     */
    private Long moduleCount;

    /**
     * Number of runtime dependencies of a product.
     */
    private Long runtimeDepCount;

    /**
     * Number of all distinct vulnerabilities of a product.
     */
    private Long vulCount;

    /**
     * Number of all distinct licenses of a product.
     */
    private Long licenseCount;

    /**
     * Number of all distinct critical vulnerabilities of a product.
     * Vulnerability severity classification: <a href="https://nvd.nist.gov/vuln-metrics/cvss">nvd cvss metrics</a>
     */
    private Long criticalVulCount;

    /**
     * Number of all distinct high vulnerabilities of a product.
     */
    private Long highVulCount;

    /**
     * Number of all distinct medium vulnerabilities of a product.
     */
    private Long mediumVulCount;

    /**
     * Number of all distinct low vulnerabilities of a product.
     */
    private Long lowVulCount;

    /**
     * Number of all distinct none vulnerabilities of a product.
     */
    private Long noneVulCount;

    /**
     * Number of all distinct unknown vulnerabilities of a product.
     */
    private Long unknownVulCount;

    /**
     * Number of packages whose most severe vulnerability is critical of a product.
     */
    private Long packageWithCriticalVulCount;

    /**
     * Number of packages whose most severe vulnerability is high of a product.
     */
    private Long packageWithHighVulCount;

    /**
     * Number of packages whose most severe vulnerability is medium of a product.
     */
    private Long packageWithMediumVulCount;

    /**
     * Number of packages whose most severe vulnerability is low of a product.
     */
    private Long packageWithLowVulCount;

    /**
     * Number of packages whose most severe vulnerability is none of a product.
     */
    private Long packageWithNoneVulCount;

    /**
     * Number of packages whose most severe vulnerability is unknown of a product.
     */
    private Long packageWithUnknownVulCount;

    /**
     * Number of packages not affected by any vulnerability of a product.
     */
    private Long packageWithoutVulCount;

    /**
     * Number of packages with legal license of a product.
     */
    private Long packageWithLegalLicenseCount;

    /**
     * Number of packages with illegal license of a product.
     */
    private Long packageWithIllegalLicenseCount;

    /**
     * Number of packages without license of a product.
     */
    private Long packageWithoutLicenseCount;

    /**
     * Number of packages with multiple licenses of a product.
     */
    private Long packageWithMultiLicenseCount;

    /**
     * Distribution of licenses.
     * { spdx-licence-id: number of packages using the license }
     */
    @Column(columnDefinition = "JSONB")
    @Type(type = "jsonb")
    private Map<String, Long> licenseDistribution;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "product_id", foreignKey = @ForeignKey(name = "product_id_fk"))
    @JsonIgnore
    private Product product;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Timestamp getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Timestamp createTime) {
        this.createTime = createTime;
    }

    public Long getPackageCount() {
        return packageCount;
    }

    public void setPackageCount(Long packageCount) {
        this.packageCount = packageCount;
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

    public Long getPackageWithCriticalVulCount() {
        return packageWithCriticalVulCount;
    }

    public void setPackageWithCriticalVulCount(Long packageWithCriticalVulCount) {
        this.packageWithCriticalVulCount = packageWithCriticalVulCount;
    }

    public Long getPackageWithHighVulCount() {
        return packageWithHighVulCount;
    }

    public void setPackageWithHighVulCount(Long packageWithHighVulCount) {
        this.packageWithHighVulCount = packageWithHighVulCount;
    }

    public Long getPackageWithMediumVulCount() {
        return packageWithMediumVulCount;
    }

    public void setPackageWithMediumVulCount(Long packageWithMediumVulCount) {
        this.packageWithMediumVulCount = packageWithMediumVulCount;
    }

    public Long getPackageWithLowVulCount() {
        return packageWithLowVulCount;
    }

    public void setPackageWithLowVulCount(Long packageWithLowVulCount) {
        this.packageWithLowVulCount = packageWithLowVulCount;
    }

    public Long getPackageWithNoneVulCount() {
        return packageWithNoneVulCount;
    }

    public void setPackageWithNoneVulCount(Long packageWithNoneVulCount) {
        this.packageWithNoneVulCount = packageWithNoneVulCount;
    }

    public Long getPackageWithUnknownVulCount() {
        return packageWithUnknownVulCount;
    }

    public void setPackageWithUnknownVulCount(Long packageWithUnknownVulCount) {
        this.packageWithUnknownVulCount = packageWithUnknownVulCount;
    }

    public Long getPackageWithoutVulCount() {
        return packageWithoutVulCount;
    }

    public void setPackageWithoutVulCount(Long packageWithoutVulCount) {
        this.packageWithoutVulCount = packageWithoutVulCount;
    }

    public Long getPackageWithLegalLicenseCount() {
        return packageWithLegalLicenseCount;
    }

    public void setPackageWithLegalLicenseCount(Long packageWithLegalLicenseCount) {
        this.packageWithLegalLicenseCount = packageWithLegalLicenseCount;
    }

    public Long getPackageWithIllegalLicenseCount() {
        return packageWithIllegalLicenseCount;
    }

    public void setPackageWithIllegalLicenseCount(Long packageWithIllegalLicenseCount) {
        this.packageWithIllegalLicenseCount = packageWithIllegalLicenseCount;
    }

    public Long getPackageWithoutLicenseCount() {
        return packageWithoutLicenseCount;
    }

    public void setPackageWithoutLicenseCount(Long packageWithoutLicenseCount) {
        this.packageWithoutLicenseCount = packageWithoutLicenseCount;
    }

    public Long getPackageWithMultiLicenseCount() {
        return packageWithMultiLicenseCount;
    }

    public void setPackageWithMultiLicenseCount(Long packageWithMultiLicenseCount) {
        this.packageWithMultiLicenseCount = packageWithMultiLicenseCount;
    }

    public Map<String, Long> getLicenseDistribution() {
        return licenseDistribution;
    }

    public void setLicenseDistribution(Map<String, Long> licenseDistribution) {
        this.licenseDistribution = licenseDistribution;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }
}
