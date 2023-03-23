package org.opensourceway.sbom.model.pojo.vo.sbom;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

public class BinaryManagementVo implements Serializable {

    private List<BinaryManagementItemVo> packageList = Collections.emptyList();

    private List<BinaryManagementItemVo> provideList = Collections.emptyList();

    private List<BinaryManagementItemVo> externalList = Collections.emptyList();

    private List<BinaryManagementItemVo> relationshipList = Collections.emptyList();

    public List<BinaryManagementItemVo> getPackageList() {
        return packageList;
    }

    public void setPackageList(List<BinaryManagementItemVo> packageList) {
        this.packageList = packageList;
    }

    public List<BinaryManagementItemVo> getProvideList() {
        return provideList;
    }

    public void setProvideList(List<BinaryManagementItemVo> provideList) {
        this.provideList = provideList;
    }

    public List<BinaryManagementItemVo> getExternalList() {
        return externalList;
    }

    public void setExternalList(List<BinaryManagementItemVo> externalList) {
        this.externalList = externalList;
    }

    public List<BinaryManagementItemVo> getRelationshipList() {
        return relationshipList;
    }

    public void setRelationshipList(List<BinaryManagementItemVo> relationshipList) {
        this.relationshipList = relationshipList;
    }
}
