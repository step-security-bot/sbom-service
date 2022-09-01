package org.opensourceway.sbom.manager.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.RawSbom;
import org.opensourceway.sbom.manager.model.vo.BinaryManagementVo;
import org.opensourceway.sbom.manager.model.vo.PackagePurlVo;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.model.vo.PageVo;
import org.opensourceway.sbom.manager.model.vo.ProductConfigVo;
import org.opensourceway.sbom.manager.model.vo.VulnerabilityVo;
import org.opensourceway.sbom.manager.model.vo.request.PublishSbomRequest;
import org.opensourceway.sbom.manager.model.vo.response.PublishResultResponse;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface SbomService {

    UUID publishSbom(PublishSbomRequest publishSbomRequest);

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

    void persistSbomFromTraceData(String productName, String fileName, InputStream inputStream) throws IOException;
}
