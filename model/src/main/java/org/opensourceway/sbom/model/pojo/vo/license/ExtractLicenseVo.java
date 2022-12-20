package org.opensourceway.sbom.model.pojo.vo.license;

import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgLicenseRelp;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ExtractLicenseVo {
    private Set<Package> packages = new HashSet<>();

    private Set<License> licenses = new HashSet<>();

    /**
     * Spdx-license-id of the license in the relationship
     */
    private Map<PkgLicenseRelp, String> licenseOfRelp = new HashMap<>();

    public Set<Package> getPackages() {
        return packages;
    }

    public void setPackages(Set<Package> packages) {
        this.packages = packages;
    }

    public void addPackage(Package pkg) {
        packages.add(pkg);
    }

    public Set<License> getLicenses() {
        return licenses;
    }

    public void setLicenses(Set<License> licenses) {
        this.licenses = licenses;
    }

    public void addLicense(License license) {
        licenses.add(license);
    }

    public Map<PkgLicenseRelp, String> getLicenseOfRelp() {
        return licenseOfRelp;
    }

    public void setLicenseOfRelp(Map<PkgLicenseRelp, String> licenseOfRelp) {
        this.licenseOfRelp = licenseOfRelp;
    }

    public void putPkgLicenseRelp(PkgLicenseRelp relp, String spdxLicenseId) {
        licenseOfRelp.put(relp, spdxLicenseId);
    }
}
