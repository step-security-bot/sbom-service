package org.opensourceway.sbom.manager.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.manager.TestConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.ProductTypeRepository;
import org.opensourceway.sbom.manager.dao.RawSbomRepository;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.ProductConfig;
import org.opensourceway.sbom.manager.model.ProductType;
import org.opensourceway.sbom.manager.model.RawSbom;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.vo.BinaryManagementVo;
import org.opensourceway.sbom.manager.model.vo.PackagePurlVo;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.model.vo.PageVo;
import org.opensourceway.sbom.manager.model.vo.ProductConfigVo;
import org.opensourceway.sbom.manager.model.vo.VulnerabilityVo;
import org.opensourceway.sbom.manager.model.vo.request.PublishSbomRequest;
import org.opensourceway.sbom.manager.model.vo.response.PublishResultResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SbomServiceTest {

    @Autowired
    private SbomService sbomService;

    @Autowired
    private ProductTypeRepository productTypeRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private RawSbomRepository rawSbomRepository;

    private static String packageId = null;

    private void getPackageId() {
        if (SbomServiceTest.packageId != null) {
            return;
        }

        List<Package> packagesList = sbomService.queryPackageInfoByName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME, TestConstants.BINARY_TEST_PACKAGE_NAME, true);
        assertThat(packagesList).isNotEmpty();

        SbomServiceTest.packageId = packagesList.get(0).getId().toString();
    }

    @Test
    public void getAllCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, null);
        assertThat(vo.getPackageList().size()).isEqualTo(1);
        assertThat(vo.getProvideList().size()).isGreaterThan(1);
        assertThat(vo.getExternalList().size()).isGreaterThan(1);
    }

    @Test
    public void getPackageCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.PACKAGE_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(1);
        assertThat(vo.getProvideList().size()).isEqualTo(0);
        assertThat(vo.getExternalList().size()).isEqualTo(0);
    }

    @Test
    public void getProvideCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.PROVIDE_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isGreaterThan(1);
        assertThat(vo.getExternalList().size()).isEqualTo(0);
    }

    @Test
    public void getExternalCategoryRef() {
        if (SbomServiceTest.packageId == null) {
            getPackageId();
        }
        BinaryManagementVo vo = sbomService.queryPackageBinaryManagement(SbomServiceTest.packageId, ReferenceCategory.EXTERNAL_MANAGER.name());
        assertThat(vo.getPackageList().size()).isEqualTo(0);
        assertThat(vo.getProvideList().size()).isEqualTo(0);
        assertThat(vo.getExternalList().size()).isGreaterThan(1);
    }


    @Test
    public void queryPackageInfoByBinaryExactlyTest() {
        PackageUrlVo purl = new PackageUrlVo("maven",
                "org.apache.zookeeper",
                "zookeeper",
                "3.4.6");
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                purl,
                pageable);
        assertThat(result.getTotalElements()).isEqualTo(1);
    }

    @Test
    public void queryPackageInfoByBinaryWithoutVersionTest() {
        PackageUrlVo purl = new PackageUrlVo("maven",
                "org.apache.zookeeper",
                "zookeeper",
                "");
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                purl,
                pageable);
        assertThat(result.getTotalElements()).isEqualTo(7);
    }

    @Test
    public void queryPackageInfoByBinaryOnlyNameTest() {
        PackageUrlVo purl = new PackageUrlVo("maven",
                "",
                "zookeeper",
                "");
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                purl,
                pageable);
        assertThat(result.getTotalElements()).isEqualTo(9);
    }

    @Test
    public void queryPackageInfoByBinaryChecksumTest() {
        PackageUrlVo purl = new PackageUrlVo("maven",
                "sqlline",
                "sqlline",
                "1.3.0");
        // use checksum type, to:pkg:maven/sha1/2a2d713f56de83f4e84fab07a7edfbfcebf403af@1.0.0
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                purl,
                pageable);
        assertThat(result.getTotalElements()).isEqualTo(0);
    }

    @Test
    public void queryPackageInfoByBinaryChecksumTest1() {
        // actual purl value: pkg:maven/sqlline/sqlline@1.3.0
        PackageUrlVo purl = new PackageUrlVo("maven",
                "sha1",
                "2a2d713f56de83f4e84fab07a7edfbfcebf403af",
                "1.0.0");
        Pageable pageable = PageRequest.of(0, 15);

        PageVo<PackagePurlVo> result = sbomService.queryPackageInfoByBinaryViaSpec(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                purl,
                pageable);
        assertThat(result.getTotalElements()).isEqualTo(0);
    }

    @Test
    public void queryPackageInfoByBinaryViaSpecFullComponent() {
        PageVo<PackagePurlVo> refs = sbomService.queryPackageInfoByBinaryViaSpec(
                TestConstants.SAMPLE_PRODUCT_NAME,
                ReferenceCategory.PACKAGE_MANAGER.name(),
                new PackageUrlVo("gitee",
                        "mindspore",
                        "akg",
                        "1.7.0"),
                PageRequest.of(0, 15));
        assertThat(refs.getTotalElements()).isEqualTo(1);
    }

    @Test
    public void queryPackageInfoByBinaryViaSpecNotExists() {
        PageVo<PackagePurlVo> refs = sbomService.queryPackageInfoByBinaryViaSpec(
                TestConstants.SAMPLE_PRODUCT_NAME,
                ReferenceCategory.PACKAGE_MANAGER.name(),
                new PackageUrlVo("gitee",
                        "mindspore",
                        "akg",
                        "x.7.0"),
                PageRequest.of(0, 15));
        assertThat(refs.getTotalElements()).isEqualTo(0);
    }

    @Test
    public void queryProductType() {
        ProductType productType = new ProductType();
        productType.setType("test_type_1");
        ProductType ret = productTypeRepository.save(productType);

        List<String> productTypes = sbomService.queryProductType();
        assertThat(productTypes.contains("test_type_1")).isTrue();

        productTypeRepository.delete(ret);
    }

    @Test
    public void queryProductConfigByProductType() {
        ProductType productType = new ProductType();
        productType.setType("test_type_2");

        ProductConfig config_1 = new ProductConfig();
        config_1.setProductType(productType);
        config_1.setValueType("String");
        config_1.setOrd(1);
        config_1.setName("os");
        config_1.setLabel("操作系统");

        ProductConfig config_2 = new ProductConfig();
        config_2.setProductType(productType);
        config_2.setValueType("String");
        config_2.setOrd(2);
        config_2.setName("arch");
        config_2.setLabel("系统架构");

        productType.setProductConfigs(List.of(config_1, config_2));
        ProductType ret = productTypeRepository.save(productType);

        List<ProductConfigVo> configVos = sbomService.queryProductConfigByProductType("test_type_2");
        assertThat(configVos.get(0).getName()).isEqualTo("os");
        assertThat(configVos.get(0).getLabel()).isEqualTo("操作系统");
        assertThat(configVos.get(0).getValueType()).isEqualTo("String");
        assertThat(configVos.get(0).getOrd()).isEqualTo(1);
        assertThat(configVos.get(1).getName()).isEqualTo("arch");
        assertThat(configVos.get(1).getLabel()).isEqualTo("系统架构");
        assertThat(configVos.get(1).getValueType()).isEqualTo("String");
        assertThat(configVos.get(1).getOrd()).isEqualTo(2);

        productTypeRepository.delete(ret);
    }

    @Test
    public void queryProductByFullAttributes() throws JsonProcessingException {
        Product product = new Product();
        product.setName("test_product");
        product.setAttribute(Map.of("os", "linux", "arch", "x86_64", "test", 1));
        Product ret = productRepository.save(product);

        Product product_found = sbomService.queryProductByFullAttributes(Map.of("os", "linux", "arch", "x86_64", "test", 1));
        assertThat(product_found.getName()).isEqualTo("test_product");
        assertThat(product_found.getAttribute().get("os")).isEqualTo("linux");
        assertThat(product_found.getAttribute().get("arch")).isEqualTo("x86_64");
        assertThat(product_found.getAttribute().get("test")).isEqualTo(1);

        productRepository.delete(ret);
    }

    @Test
    public void queryVulnerabilityByPackageId() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        PageVo<VulnerabilityVo> result = sbomService.queryVulnerabilityByPackageId(pkg.getId().toString(), PageRequest.of(0, 15, Sort.by("all_vul.v_vul_id")));
        assertThat(result).isNotEmpty();
        assertThat(result.getTotalElements()).isEqualTo(3);
        assertThat(result.getTotalPages()).isEqualTo(1);

        assertThat(result.getContent().get(0).getVulId()).isEqualTo("CVE-2022-00000-test");
        assertThat(result.getContent().get(0).getScoringSystem()).isEqualTo("CVSS3");
        assertThat(result.getContent().get(0).getScore()).isEqualTo(5.3);
        assertThat(result.getContent().get(0).getVector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
        assertThat(result.getContent().get(0).getPurl()).isEqualTo("pkg:pypi/asttokens@2.0.5");
        assertThat(result.getContent().get(0).getReferences().size()).isEqualTo(2);
        assertThat(result.getContent().get(0).getReferences().get(0).getFirst()).isEqualTo("NVD");
        assertThat(result.getContent().get(0).getReferences().get(0).getSecond()).isEqualTo("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00000-test");
        assertThat(result.getContent().get(0).getReferences().get(1).getFirst()).isEqualTo("OSS_INDEX");
        assertThat(result.getContent().get(0).getReferences().get(1).getSecond()).isEqualTo("https://ossindex.sonatype.org/vulnerability/sonatype-2022-00000-test");

        assertThat(result.getContent().get(1).getVulId()).isEqualTo("CVE-2022-00001-test");
        assertThat(result.getContent().get(1).getScoringSystem()).isEqualTo("CVSS2");
        assertThat(result.getContent().get(1).getScore()).isEqualTo(9.8);
        assertThat(result.getContent().get(1).getVector()).isEqualTo("(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)");
        assertThat(result.getContent().get(0).getPurl()).isEqualTo("pkg:pypi/asttokens@2.0.5");
        assertThat(result.getContent().get(1).getReferences().size()).isEqualTo(1);
        assertThat(result.getContent().get(1).getReferences().get(0).getFirst()).isEqualTo("NVD");
        assertThat(result.getContent().get(1).getReferences().get(0).getSecond()).isEqualTo("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00001-test");

        assertThat(result.getContent().get(2).getVulId()).isEqualTo("CVE-2022-00002-test");
        assertThat(result.getContent().get(2).getScoringSystem()).isNull();
        assertThat(result.getContent().get(2).getScore()).isNull();
        assertThat(result.getContent().get(2).getVector()).isNull();
        assertThat(result.getContent().get(0).getPurl()).isEqualTo("pkg:pypi/asttokens@2.0.5");
        assertThat(result.getContent().get(2).getReferences().size()).isEqualTo(2);
        assertThat(result.getContent().get(2).getReferences().get(0).getFirst()).isEqualTo("NVD");
        assertThat(result.getContent().get(2).getReferences().get(0).getSecond()).isEqualTo("http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00002-test");
        assertThat(result.getContent().get(2).getReferences().get(1).getFirst()).isEqualTo("GITHUB");
        assertThat(result.getContent().get(2).getReferences().get(1).getSecond()).isEqualTo("https://github.com/xxx/xxx/security/advisories/xxx");

    }

    @Test
    public void persistSbomFromTraceData() throws IOException {

        sbomService.persistSbomFromTraceData(
                TestConstants.SAMPLE_MINDSPORE_TRACER_PRODUCT_NAME,
                TestConstants.SAMPLE_UPLOAD_TRACE_DATA_NAME,
                new ClassPathResource(TestConstants.SAMPLE_UPLOAD_TRACE_DATA_NAME).getInputStream());

        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_MINDSPORE_TRACER_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        assertThat(sbom.getName()).isEqualTo("mindsporeTracerTest");

        List<Package> packages = sbom.getPackages();
        assertThat(packages.size()).isEqualTo(2);

        Package akg = packages.stream().filter(p -> StringUtils.equals(p.getName(), "akg")).findFirst().orElse(null);
        assertThat(akg).isNotNull();
        assertThat(akg.getSpdxId()).isEqualTo("SPDXRef-Package-gitee-mindspore-akg-1.7.0");
        assertThat(akg.getVersion()).isEqualTo("1.7.0");

        Package protobuf = packages.stream().filter(p -> StringUtils.equals(p.getName(), "protobuf")).findFirst().orElse(null);
        assertThat(protobuf).isNotNull();
        assertThat(protobuf.getSpdxId()).isEqualTo("SPDXRef-Package-github-protocolbuffers-protobuf-3.13.0");
        assertThat(protobuf.getVersion()).isEqualTo("3.13.0");
    }

    @Test
    @Order(1)
    public void republishWaitingSbom() throws IOException {
        PublishSbomRequest request = new PublishSbomRequest();
        request.setProductName(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);
        request.setSbomContent(IOUtils.toString(new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME).getInputStream(), Charset.defaultCharset()));

        UUID taskId = sbomService.publishSbom(request);
        PublishResultResponse response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        UUID taskIdRepublish = sbomService.publishSbom(request);
        assertThat(taskId).isEqualTo(taskIdRepublish);
        response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        RawSbom rawSbom = rawSbomRepository.findByTaskId(taskId).orElse(null);
        if (Objects.nonNull(rawSbom)) {
            rawSbomRepository.delete(rawSbom);
        }
    }

    @Test
    @Order(2)
    public void republishFinishedSbom() throws IOException {
        PublishSbomRequest request = new PublishSbomRequest();
        request.setProductName(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);
        request.setSbomContent(IOUtils.toString(new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME).getInputStream(), Charset.defaultCharset()));

        UUID taskId = sbomService.publishSbom(request);
        PublishResultResponse response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        RawSbom rawSbom = rawSbomRepository.findByTaskId(taskId).orElseThrow(() -> new RuntimeException(""));
        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_FINISH);
        rawSbomRepository.save(rawSbom);
        response = sbomService.getSbomPublishResult(taskId);
        assertThat(response.getSbomRef()).contains(TestConstants.PUBLISH_SAMPLE_FOR_SERVICE_PRODUCT_NAME);
        assertThat(response.getFinish()).isTrue();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        UUID taskIdRepublish = sbomService.publishSbom(request);
        assertThat(taskId).isNotEqualTo(taskIdRepublish);
        response = sbomService.getSbomPublishResult(taskIdRepublish);
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isNull();
        assertThat(response.getSuccess()).isTrue();

        RawSbom rawSbomDelete = rawSbomRepository.findByTaskId(taskIdRepublish).orElse(null);
        if (Objects.nonNull(rawSbomDelete)) {
            rawSbomRepository.delete(rawSbomDelete);
        }
    }

    @Test
    @Order(3)
    public void getSbomPublishResultNotExist() {
        PublishResultResponse response = sbomService.getSbomPublishResult(UUID.fromString("12341234-1234-1234-1234-123412341234"));
        assertThat(response.getSbomRef()).isNull();
        assertThat(response.getFinish()).isFalse();
        assertThat(response.getErrorInfo()).isEqualTo(SbomConstants.TASK_STATUS_NOT_EXISTS);
        assertThat(response.getSuccess()).isFalse();
    }
}
