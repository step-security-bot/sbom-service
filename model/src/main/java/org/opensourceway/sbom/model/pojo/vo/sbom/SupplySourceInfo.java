package org.opensourceway.sbom.model.pojo.vo.sbom;

import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SupplySourceInfo implements Serializable {

    List<Package> pkgList = new ArrayList<>();

    Set<File> fileList = new HashSet<>();

    Set<SbomElementRelationship> relationshipList = new HashSet<>();

    public List<Package> getPkgList() {
        return pkgList;
    }

    public void addPkg(Package pkg) {
        this.pkgList.add(pkg);
    }

    public void addPkgs(List<Package> pkgs) {
        this.pkgList.addAll(pkgs);
    }

    public void setPkgList(List<Package> pkgList) {
        this.pkgList = pkgList;
    }

    public Set<File> getFileList() {
        return fileList;
    }

    public void addFile(File file) {
        this.fileList.add(file);
    }

    public void addFiles(List<File> files) {
        this.fileList.addAll(files);
    }

    public void setFileList(Set<File> fileList) {
        this.fileList = fileList;
    }

    public Set<SbomElementRelationship> getRelationshipList() {
        return relationshipList;
    }

    public void addRelationship(SbomElementRelationship relationship) {
        this.relationshipList.add(relationship);
    }

    public void addRelationships(List<SbomElementRelationship> relationships) {
        this.relationshipList.addAll(relationships);
    }

    public void setRelationshipList(Set<SbomElementRelationship> relationshipList) {
        this.relationshipList = relationshipList;
    }
}
