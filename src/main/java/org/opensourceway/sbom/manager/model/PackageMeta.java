package org.opensourceway.sbom.manager.model;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.Table;
import java.util.Map;
import java.util.UUID;

/**
 * Package metadata obtained from external sources.
 */
@Entity
@TypeDefs({
        @TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
})
@Table(indexes = {
        @Index(name = "check_sum_uk", columnList = "checksum", unique = true)
})
public class PackageMeta {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Checksum of a package.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String checksum;

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

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
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