package org.openeuler.sbom.manager.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.Product;
import org.openeuler.sbom.manager.model.RawSbom;
import org.openeuler.sbom.manager.model.vo.BinaryManagementVo;
import org.openeuler.sbom.manager.model.vo.PackagePurlVo;
import org.openeuler.sbom.manager.model.vo.PackageUrlVo;
import org.openeuler.sbom.manager.model.vo.PageVo;
import org.openeuler.sbom.manager.model.vo.ProductConfigVo;
import org.openeuler.sbom.manager.model.vo.VulnerabilityVo;
import org.openeuler.sbom.manager.model.vo.request.PublishSbomRequest;
import org.openeuler.sbom.manager.model.vo.response.PublishResultResponse;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface SbomService {

    UUID publishSbom(PublishSbomRequest publishSbomRequest) throws IOException;

    PublishResultResponse getSbomPublishResult(UUID taskId);

    void readSbomFile(String productName, String fileName, byte[] fileContent) throws IOException;

    RawSbom writeSbomFile(String productName, String spec, String specVersion, String format);

    byte[] writeSbom(String productName, String spec, String specVersion, String format) throws IOException;

    PageVo<Package> findPackagesPageable(String productName, int page, int size);

    List<Package> queryPackageInfoByName(String productName, String packageName, boolean isExactly);

    Package queryPackageInfoById(String packageId);

    PageVo<Package> getPackageInfoByNameForPage(String productName, String packageName, Boolean isEqual, int page, int size);

    BinaryManagementVo queryPackageBinaryManagement(String packageId, String binaryType);

    @Deprecated
    PageVo<PackagePurlVo> queryPackageInfoByBinary(String productName,
                                                   String binaryType,
                                                   PackageUrlVo purl,
                                                   Pageable pageable) throws Exception;

    PageVo<PackagePurlVo> queryPackageInfoByBinaryViaSpec(String productName,
                                                          String binaryType,
                                                          PackageUrlVo purl,
                                                          Pageable pageable);

    List<String> queryProductType();

    List<ProductConfigVo> queryProductConfigByProductType(String productType);

    Product queryProductByFullAttributes(Map<String, ?> attributes) throws JsonProcessingException;

    PageVo<VulnerabilityVo> queryVulnerabilityByPackageId(String packageId, Pageable pageable);

}
