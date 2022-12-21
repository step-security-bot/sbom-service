package org.opensourceway.sbom.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.sql.Timestamp;
import java.util.UUID;

@Entity
@Table(indexes = {
        @Index(name = "raw_sbom_uk", columnList = "value_type, product_id", unique = true)
})
public class RawSbom {
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @Column(columnDefinition = "TEXT", name = "value_type", nullable = false)
    private String valueType;

    @Column(columnDefinition = "BYTEA", nullable = false)
    @Lob
    @Type(type = "org.hibernate.type.BinaryType")
    private byte[] value;

    @ManyToOne(optional = false)
    @JoinColumn(name = "product_id", foreignKey = @ForeignKey(name = "product_id_fk"))
    @JsonIgnore
    private Product product;

    @Column(name = "create_time", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    @CreationTimestamp
    private Timestamp createTime;

    @Column(name = "update_time", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    @UpdateTimestamp
    private Timestamp updateTime;

    @Column(columnDefinition = "TEXT", name = "task_status")
    private String taskStatus;

    @Column(columnDefinition = "UUID", name = "task_id")
    private UUID taskId;

    @Column(name = "job_execution_id")
    private Long jobExecutionId;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getValueType() {
        return valueType;
    }

    public void setValueType(String valueType) {
        this.valueType = valueType;
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public Timestamp getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Timestamp createTime) {
        this.createTime = createTime;
    }

    public Timestamp getUpdateTime() {
        return updateTime;
    }

    public void setUpdateTime(Timestamp updateTime) {
        this.updateTime = updateTime;
    }

    public String getTaskStatus() {
        return taskStatus;
    }

    public void setTaskStatus(String taskStatus) {
        this.taskStatus = taskStatus;
    }

    public UUID getTaskId() {
        return taskId;
    }

    public void setTaskId(UUID taskId) {
        this.taskId = taskId;
    }

    public Long getJobExecutionId() {
        return jobExecutionId;
    }

    public void setJobExecutionId(Long jobExecutionId) {
        this.jobExecutionId = jobExecutionId;
    }

}
