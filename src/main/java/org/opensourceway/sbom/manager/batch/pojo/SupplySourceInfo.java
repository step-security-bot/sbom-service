package org.opensourceway.sbom.manager.batch.pojo;

import org.opensourceway.sbom.manager.model.File;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.SbomElementRelationship;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class SupplySourceInfo implements Serializable {

    List<Package> pkgList = new ArrayList<>();

    List<File> fileList = new ArrayList<>();

    List<SbomElementRelationship> relationshipList = new ArrayList<>();

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

    public List<File> getFileList() {
        return fileList;
    }

    public void addFile(File file) {
        this.fileList.add(file);
    }

    public void addFiles(List<File> files) {
        this.fileList.addAll(files);
    }

    public void setFileList(List<File> fileList) {
        this.fileList = fileList;
    }

    public List<SbomElementRelationship> getRelationshipList() {
        return relationshipList;
    }

    public void addRelationship(SbomElementRelationship relationship) {
        this.relationshipList.add(relationship);
    }

    public void addRelationships(List<SbomElementRelationship> relationships) {
        this.relationshipList.addAll(relationships);
    }

    public void setRelationshipList(List<SbomElementRelationship> relationshipList) {
        this.relationshipList = relationshipList;
    }
}
