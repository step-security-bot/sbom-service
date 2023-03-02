package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Describes a sbom document.
 */
@Entity
@Table(indexes = {
        @Index(name = "product_id_uk", columnList = "product_id", unique = true)
})
public class Sbom {

    public Sbom() {
    }

    public Sbom(Product product) {
        this.product = product;
    }

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Name of a sbom document.
     */
    @Column(columnDefinition = "TEXT")
    private String name;

    /**
     * The data license of a sbom document.
     */
    @Column(columnDefinition = "TEXT", name = "data_license")
    private String dataLicense;

    /**
     * A URI provides an unambiguous mechanism for other sbom documents to reference sbom elements within this sbom document.
     */
    @Column(columnDefinition = "TEXT")
    private String namespace;

    /**
     * Identify when the sbom file was originally created.
     * Format: YYYY-MM-DDThh:mm:ssZ
     */
    @Column(columnDefinition = "TEXT")
    private String created;

    /**
     * The version of SPDX license list (<a href="https://spdx.dev/licenses/">...</a>) used in the related sbom document.
     * Data Format: "M.N"
     */
    @Column(columnDefinition = "TEXT", name = "license_list_version")
    private String licenseListVersion;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "product_id", foreignKey = @ForeignKey(name = "product_id_fk"))
    @JsonIgnore
    private Product product;

    /**
     * Packages referred in a sbom document.
     */
    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Package> packages;

    /**
     * The list of subjects who created the related sbom document. At least one must be provided.
     */
    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SbomCreator> sbomCreators;

    /**
     * Element relationships in a sbom document.
     */
    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SbomElementRelationship> sbomElementRelationships;

    @OneToMany(mappedBy = "sbom", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<File> files;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDataLicense() {
        return dataLicense;
    }

    public void setDataLicense(String dataLicense) {
        this.dataLicense = dataLicense;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getLicenseListVersion() {
        return licenseListVersion;
    }

    public void setLicenseListVersion(String licenseListVersion) {
        this.licenseListVersion = licenseListVersion;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public List<Package> getPackages() {
        return packages;
    }

    public void setPackages(List<Package> packages) {
        if (Objects.isNull(this.packages)) {
            this.packages = packages;
        } else {
            this.packages.clear();
            this.packages.addAll(packages);
        }
    }

    public List<SbomCreator> getSbomCreators() {
        return sbomCreators;
    }

    public void setSbomCreators(List<SbomCreator> sbomCreators) {
        if (Objects.isNull(this.sbomCreators)) {
            this.sbomCreators = sbomCreators;
        } else {
            this.sbomCreators.clear();
            this.sbomCreators.addAll(sbomCreators);
        }
    }

    public List<SbomElementRelationship> getSbomElementRelationships() {
        return sbomElementRelationships;
    }

    public void setSbomElementRelationships(List<SbomElementRelationship> sbomElementRelationships) {
        if (Objects.isNull(this.sbomElementRelationships)) {
            this.sbomElementRelationships = sbomElementRelationships;
        } else {
            this.sbomElementRelationships.clear();
            this.sbomElementRelationships.addAll(sbomElementRelationships);
        }
    }

    public List<File> getFiles() {
        return files;
    }

    public void setFiles(List<File> files) {
        this.files = files;
    }
}
