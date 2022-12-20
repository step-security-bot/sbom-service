package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Describes a file referenced.
 */
@Entity
@Table(indexes = {
        @Index(name = "file_uk", columnList = "sbom_id, spdx_id, file_name", unique = true),
        @Index(name = "file_name_idx", columnList = "sbom_id, file_name")
})
public class File {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * A unique identifier for a file within a sbom document.
     */
    @Column(columnDefinition = "TEXT", name = "spdx_id", nullable = false)
    private String spdxId;

    /**
     * Name of a package, e.g., "./package/foo.c", "https://gitee.com/src-openeuler/xxx-modules/blob/openEuler-22.03-LTS/openeuler-20200527.patch".
     */
    @Column(columnDefinition = "TEXT", name = "file_name", nullable = false)
    private String fileName;

    @Column(columnDefinition = "TEXT[]", name = "file_types")
    private String[] fileTypes;

//    /**
//     * Checksums of a file.
//     */
//    @OneToMany(mappedBy = "file", cascade = CascadeType.ALL, orphanRemoval = true)
//    @JsonIgnore
//    private List<Checksum> checksums;

    /**
     * Identify the copyright holder of the file, as well as any dates present. This shall be a free-form text field extracted from the actual file.
     */
    @Column(columnDefinition = "TEXT", name = "copyright_text")
    private String copyrightText;

    @Column(columnDefinition = "TEXT[]", name = "license_info_in_files")
    private String[] licenseInfoInFiles;

    /**
     * This field contains the license the SPDX document creator has concluded as governing the file or alternative values if the governing license cannot be determined.
     */
    @Column(columnDefinition = "TEXT", name = "license_concluded")
    private String licenseConcluded;

    /**
     * This field provides a place for the SPDX document creator to record any relevant background references or analysis that went in to arriving at the Concluded License for a file. If the Concluded License does not match the License Information in File, this should be explained by the SPDX document creator.
     */
    @Column(columnDefinition = "TEXT", name = "license_comments")
    private String licenseComments;

    /**
     * Sbom that a file belongs to.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sbom_id", foreignKey = @ForeignKey(name = "sbom_id_fk"))
    @JsonIgnore
    private Sbom sbom;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getSpdxId() {
        return spdxId;
    }

    public void setSpdxId(String spdxId) {
        this.spdxId = spdxId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String[] getFileTypes() {
        return fileTypes;
    }

    public void setFileTypes(String[] fileTypes) {
        this.fileTypes = fileTypes;
    }

    public String getCopyrightText() {
        return copyrightText;
    }

    public void setCopyrightText(String copyrightText) {
        this.copyrightText = copyrightText;
    }

    public String[] getLicenseInfoInFiles() {
        return licenseInfoInFiles;
    }

    public void setLicenseInfoInFiles(String[] licenseInfoInFiles) {
        this.licenseInfoInFiles = licenseInfoInFiles;
    }

    public String getLicenseConcluded() {
        return licenseConcluded;
    }

    public void setLicenseConcluded(String licenseConcluded) {
        this.licenseConcluded = licenseConcluded;
    }

    public String getLicenseComments() {
        return licenseComments;
    }

    public void setLicenseComments(String licenseComments) {
        this.licenseComments = licenseComments;
    }

    public Sbom getSbom() {
        return sbom;
    }

    public void setSbom(Sbom sbom) {
        this.sbom = sbom;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        File file = (File) o;
        return Objects.equals(spdxId, file.spdxId)
                && Objects.equals(fileName, file.fileName)
                && Objects.equals(Optional.ofNullable(sbom).orElse(new Sbom()).getId(), Optional.ofNullable(file.sbom).orElse(new Sbom()).getId());
    }

    @Override
    public int hashCode() {
        return Objects.hash(spdxId, fileName, Optional.ofNullable(sbom).orElse(new Sbom()).getId());
    }
}
