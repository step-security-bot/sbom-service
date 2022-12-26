package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;
import org.hibernate.annotations.TypeDefs;
import org.opensourceway.sbom.model.constants.BatchContextConstants;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Describes a product.
 */
@Entity
@TypeDefs({
        @TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
})
@Table(indexes = {
        @Index(name = "name_uk", columnList = "name", unique = true),
        @Index(name = "attr_uk", columnList = "attribute", unique = true)
})
public class Product {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Name of a product.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String name;

    @OneToOne(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private Sbom sbom;

    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<RawSbom> rawSboms;

    /**
     * Attributes of a product.
     */
    @Column(columnDefinition = "JSONB", nullable = false)
    @Type(type = "jsonb")
    private Map<String, String> attribute;

    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<ProductStatistics> productStatistics;

    /**
     * Create time of a product.
     */
    @Column(columnDefinition = "TIMESTAMP WITH TIME ZONE")
    @CreationTimestamp
    private Timestamp createTime;

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

    public Sbom getSbom() {
        return sbom;
    }

    public void setSbom(Sbom sbom) {
        this.sbom = sbom;
    }

    public List<RawSbom> getRawSboms() {
        return rawSboms;
    }

    public void setRawSboms(List<RawSbom> rawSboms) {
        this.rawSboms = rawSboms;
    }

    public Map<String, String> getAttribute() {
        return attribute;
    }

    public void setAttribute(Map<String, String> attribute) {
        this.attribute = attribute;
    }

    public List<ProductStatistics> getProductStatistics() {
        return productStatistics;
    }

    public void setProductStatistics(List<ProductStatistics> productStatistics) {
        if (Objects.isNull(this.productStatistics)) {
            this.productStatistics = productStatistics;
        } else {
            this.productStatistics.clear();
            this.productStatistics.addAll(productStatistics);
        }
    }

    public void addProductStatistics(ProductStatistics productStatistics) {
        if (Objects.isNull(this.productStatistics)) {
            this.productStatistics = new ArrayList<>();
        }
        if (!this.productStatistics.contains(productStatistics)) {
            this.productStatistics.add(productStatistics);
        }
    }

    public String getProductVersion() {
        return String.valueOf(this.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY));
    }

    public String getProductType() {
        return String.valueOf(this.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_TYPE_KEY));
    }
}

