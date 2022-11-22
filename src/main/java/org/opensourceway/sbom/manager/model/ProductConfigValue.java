package org.opensourceway.sbom.manager.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.util.UUID;

/**
 * Config of a specific productType.
 */
@Entity
@Table(indexes = {
        @Index(name = "config_value_uk", columnList = "product_config_id, value", unique = true)
})
public class ProductConfigValue {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Allowed value of a product config.
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String value;

    /**
     * Product config that the config value belongs to.
     */
    @ManyToOne(optional = false)
    @JoinColumn(name = "product_config_id", foreignKey = @ForeignKey(name = "product_config_fk"))
    @JsonIgnore
    private ProductConfig productConfig;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public ProductConfig getProductConfig() {
        return productConfig;
    }

    public void setProductConfig(ProductConfig productConfig) {
        this.productConfig = productConfig;
    }
}
