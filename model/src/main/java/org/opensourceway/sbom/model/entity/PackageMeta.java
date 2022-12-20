package org.opensourceway.sbom.model.entity;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.util.Map;

/**
 * Package metadata obtained from external sources.
 */
@Entity
@TypeDefs({
        @TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
})
public class PackageMeta {
    /**
     * Checksum of a package.
     */
    @Id
    @Column(columnDefinition = "TEXT", nullable = false)
    private String checksum;

    /**
     * Checksum type.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String checksumType;

    /**
     * Purl of a package.
     */
    @Column(columnDefinition = "JSONB")
    @Type(type = "jsonb")
    private PackageUrlVo purl;

    /**
     * Extended attributes of a package.
     */
    @Column(columnDefinition = "JSONB")
    @Type(type = "jsonb")
    private Map<String, Object> extendedAttr;

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }

    public String getChecksumType() {
        return checksumType;
    }

    public void setChecksumType(String checksumType) {
        this.checksumType = checksumType;
    }

    public PackageUrlVo getPurl() {
        return purl;
    }

    public void setPurl(PackageUrlVo purl) {
        this.purl = purl;
    }

    public Map<String, Object> getExtendedAttr() {
        return extendedAttr;
    }

    public void setExtendedAttr(Map<String, Object> extendedAttr) {
        this.extendedAttr = extendedAttr;
    }
}