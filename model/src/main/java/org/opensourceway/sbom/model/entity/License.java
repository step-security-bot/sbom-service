package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Describes a license.
 */
@Entity
@Table(indexes = {
        @Index(name = "spdx_license_id_uk", columnList = "spdx_license_id", unique = true)
})
public class License {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Name of a license.
     * Multiple names may refer to the same license, e.g., both "Apache 2" and "Apache 2.0" refer to "Apache-2.0".
     */
    @Column(columnDefinition = "TEXT")
    private String name;

    /**
     * Unique identifier of a license, e.g., "Apache-2.0", "BSD-3-Clause", "GPL-3.0-only".
     */
    @Column(columnDefinition = "TEXT", name = "spdx_license_id", nullable = false)
    private String spdxLicenseId;

    /**
     * Url of a license.
     */
    @Column(columnDefinition = "TEXT")
    private String url;

    @Column(name = "is_legal")
    private Boolean isLegal;

    @OneToMany(mappedBy = "license")
    @JsonIgnore
    private Set<PkgLicenseRelp> pkgLicenseRelps;

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

    public String getSpdxLicenseId() {
        return spdxLicenseId;
    }

    public void setSpdxLicenseId(String spdxLicenseId) {
        this.spdxLicenseId = spdxLicenseId;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Boolean getIsLegal() {
        return isLegal;
    }

    public void setIsLegal(Boolean isLegal) {
        this.isLegal = isLegal;
    }

    public Set<PkgLicenseRelp> getPkgLicenseRelps() {
        return pkgLicenseRelps;
    }

    public void setPkgLicenseRelps(Set<PkgLicenseRelp> pkgLicenseRelps) {
        this.pkgLicenseRelps = pkgLicenseRelps;
    }

    public void addPkgLicenseRelp(PkgLicenseRelp pkgLicenseRelp) {
        if (Objects.isNull(pkgLicenseRelps)) {
            pkgLicenseRelps = new HashSet<>();
        }
        pkgLicenseRelps.add(pkgLicenseRelp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        License license = (License) o;
        return spdxLicenseId.equals(license.spdxLicenseId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(spdxLicenseId);
    }
}
