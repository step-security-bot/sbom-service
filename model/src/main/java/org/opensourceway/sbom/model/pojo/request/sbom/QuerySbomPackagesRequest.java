package org.opensourceway.sbom.model.pojo.request.sbom;

public class QuerySbomPackagesRequest {
    private String productName;

    private String packageName;

    private Boolean isExactly;

    private String vulSeverity;

    private Boolean noLicense;

    private Boolean multiLicense;

    private Boolean isLegalLicense;

    private String licenseId;

    private Integer page = 0;

    private Integer size = 15;

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public Boolean getExactly() {
        return isExactly;
    }

    public void setExactly(Boolean exactly) {
        isExactly = exactly;
    }

    public String getVulSeverity() {
        return vulSeverity;
    }

    public void setVulSeverity(String vulSeverity) {
        this.vulSeverity = vulSeverity;
    }

    public Boolean getNoLicense() {
        return noLicense;
    }

    public void setNoLicense(Boolean noLicense) {
        this.noLicense = noLicense;
    }

    public Boolean getMultiLicense() {
        return multiLicense;
    }

    public void setMultiLicense(Boolean multiLicense) {
        this.multiLicense = multiLicense;
    }

    public Boolean getLegalLicense() {
        return isLegalLicense;
    }

    public void setLegalLicense(Boolean legalLicense) {
        isLegalLicense = legalLicense;
    }

    public String getLicenseId() {
        return licenseId;
    }

    public void setLicenseId(String licenseId) {
        this.licenseId = licenseId;
    }

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    @Override
    public String toString() {
        return "QuerySbomPackagesRequest{" +
                "productName='" + productName + '\'' +
                ", packageName='" + packageName + '\'' +
                ", isExactly=" + isExactly +
                ", vulSeverity='" + vulSeverity + '\'' +
                ", noLicense=" + noLicense +
                ", multiLicense=" + multiLicense +
                ", isLegalLicense=" + isLegalLicense +
                ", licenseId='" + licenseId + '\'' +
                ", page=" + page +
                ", size=" + size +
                '}';
    }
}
