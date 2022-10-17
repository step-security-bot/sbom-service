package org.opensourceway.sbom.manager.controller;


import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.manager.SbomApplicationContextHolder;
import org.opensourceway.sbom.manager.SbomManagerApplication;
import org.opensourceway.sbom.manager.TestConstants;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.vo.PackageWithStatisticsVo;
import org.opensourceway.sbom.manager.service.SbomService;
import org.opensourceway.sbom.manager.utils.JsonContainsMatcher;
import org.opensourceway.sbom.utils.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
public class PkgQueryControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SbomService sbomService;

    @Autowired
    private SbomRepository sbomRepository;

    @Test
    public void queryPackagesListForPageable() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackages")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("page", "1")
                        .param("size", "15")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(false))
                .andExpect(jsonPath("$.totalElements").value(78))
                .andExpect(jsonPath("$.number").value(1))
                .andExpect(jsonPath("$.content.[0].name").value("eigen"));
    }

    @Test
    public void queryPackagesListByExactlyNameForPageable() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackages")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("packageName", TestConstants.BINARY_TEST_PACKAGE_NAME)
                        .param("isExactly", Boolean.TRUE.toString())
                        .param("page", "0")
                        .param("size", "15")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.numberOfElements").value(1))
                .andExpect(jsonPath("$.content.[0].name").value("hive"));
    }

    @Test
    public void queryPackagesListByFuzzyNameForPageable() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackages")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("packageName", TestConstants.BINARY_TEST_PACKAGE_NAME)
                        .param("isExactly", Boolean.FALSE.toString())
                        .param("page", "0")
                        .param("size", "15")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.numberOfElements").value(3))
                .andExpect(jsonPath("$.content.[0].name").value("hive"))
                .andExpect(jsonPath("$.content.[2].name").value("hivex-devel"));
    }

    @Test
    public void queryPackagesListByErrorNameForPageable() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackages")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("packageName", "hive-XXXX")
                        .param("isExactly", Boolean.FALSE.toString())
                        .param("page", "0")
                        .param("size", "15")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.totalPages").value(0))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.numberOfElements").value(0))
                .andExpect(jsonPath("$.content.*", hasSize(0)));
    }

    @Test
    public void queryPackagesListByName() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/querySbomPackages/%s/%s/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME, "pill", "false"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.*", hasSize(2)))
                .andExpect(jsonPath("$.[0].name").value("pillow"))
                .andExpect(jsonPath("$.[1].name").value("pillow"));
    }

    private static String packageId = null;

    private void getPackageId() {
        if (PkgQueryControllerTests.packageId != null) {
            return;
        }

        List<PackageWithStatisticsVo> packagesList = sbomService.queryPackageInfoByName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME, TestConstants.BINARY_TEST_PACKAGE_NAME, true);
        assertThat(packagesList).isNotEmpty();

        PkgQueryControllerTests.packageId = packagesList.get(0).getId().toString();
    }

    @Test
    public void queryPackageByIdTest() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/querySbomPackage/%s".formatted(PkgQueryControllerTests.packageId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.name").value("hive"))
                .andExpect(jsonPath("$.version").value("0:3.1.2-3.oe2203"))
                .andExpect(jsonPath("$.homepage").value("http://hive.apache.org/"));
    }

    @Test
    public void queryPackageByErrorUUIDTest() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/querySbomPackage/%s".formatted("11"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("Invalid UUID string: 11"));
    }

    @Test
    public void queryPackageByErrorIdTest() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/querySbomPackage/%s".formatted("134aaa0c-1111-1111-1111-05686b9fc20c"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("packageId:134aaa0c-1111-1111-1111-05686b9fc20c is not exist"));
    }

    @Test
    public void queryAllCategoryRef() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/queryPackageBinaryManagement/%s/%s".formatted(PkgQueryControllerTests.packageId, "all"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.packageList.*", hasSize(1)))
                .andExpect(jsonPath("$.provideList.*", hasSize(36)))
                .andExpect(jsonPath("$.externalList.*", hasSize(216)));
    }

    @Test
    public void queryPackageCategoryRef() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/queryPackageBinaryManagement/%s/%s".formatted(PkgQueryControllerTests.packageId, ReferenceCategory.PACKAGE_MANAGER.name()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.packageList.*", hasSize(1)))
                .andExpect(jsonPath("$.provideList.*", hasSize(0)))
                .andExpect(jsonPath("$.externalList.*", hasSize(0)));
    }

    @Test
    public void queryExternalCategoryRef() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/queryPackageBinaryManagement/%s/%s".formatted(PkgQueryControllerTests.packageId, ReferenceCategory.EXTERNAL_MANAGER.name()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.packageList.*", hasSize(0)))
                .andExpect(jsonPath("$.provideList.*", hasSize(0)))
                .andExpect(jsonPath("$.externalList.*", hasSize(216)));
    }

    @Test
    public void queryPackageInfoByBinaryExactlyTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "org.apache.zookeeper")
                        .param("name", "zookeeper")
                        .param("version", "3.4.6")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.content.[0].name").value("hive"));
    }

    @Test
    public void queryPackageInfoByBinaryWithoutVersionTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "org.apache.zookeeper")
                        .param("name", "zookeeper")
                        .param("version", "")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(7))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.content").value(new JsonContainsMatcher("\"name\":\"hive\"")));
    }

    @Test
    public void queryPackageInfoByBinaryOnlyNameTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "")
                        .param("name", "zookeeper")
                        .param("version", "")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(9))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.content").value(new JsonContainsMatcher("\"name\":\"hive\"")));
    }

    @Test
    public void queryPackageInfoByBinaryNoNameTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "zookeeper")
                        .param("name", "")
                        .param("version", "")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("maven purl query condition params is error, namespace: zookeeper, name: , version: , startVersion: null, endVersion: null"));
    }

    @Test
    public void queryPackageInfoByBinaryErrorTypeTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "pip")
                        .param("namespace", "")
                        .param("name", "zookeeper")
                        .param("version", "")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("purl query condition not support type: pip"));
    }

    @Test
    public void queryPackageInfoByBinaryChecksumTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "sqlline")
                        .param("name", "sqlline")
                        .param("version", "1.3.0")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.totalPages").value(0));
    }

    @Test
    public void queryPackageInfoByBinaryChecksumTest1() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "sha1")
                        .param("name", "2a2d713f56de83f4e84fab07a7edfbfcebf403af")
                        .param("version", "1.0.0")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.totalPages").value(0));
    }

    @Test
    public void queryPackageInfoByBinaryExactlyWithRangeTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "org.apache.zookeeper")
                        .param("name", "zookeeper")
                        .param("version", "3.4.6")
                        .param("startVersion", "3.4.7")
                        .param("endVersion", "3.4.8")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.size").value(15))
                .andExpect(jsonPath("$.content.[0].name").value("hive"));
    }

    @Test
    public void queryPackageInfoByBinaryRangeTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "org.apache.zookeeper")
                        .param("name", "zookeeper")
                        .param("version", "")
                        .param("startVersion", "3.4.5")
                        .param("endVersion", "3.4.7")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.size").value(50))
                .andExpect(jsonPath("$.content.[0].name").value("hive"));
    }

    @Test
    public void queryPackageInfoByBinaryStartVersionTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "org.apache.zookeeper")
                        .param("name", "zookeeper")
                        .param("version", "")
                        .param("startVersion", "3.4.5")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.size").value(50));
    }

    @Test
    public void queryPackageInfoByBinaryEndVersionTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.EXTERNAL_MANAGER.name())
                        .param("type", "maven")
                        .param("namespace", "org.apache.zookeeper")
                        .param("name", "zookeeper")
                        .param("version", "")
                        .param("endVersion", "3.4.7")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.size").value(50))
                .andExpect(jsonPath("$.content.[0].name").value("hive"));
    }

    @Test
    public void queryProductTypeTest() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductType")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.*", hasSize(3)))
                .andExpect(jsonPath("$.[0]").value("openEuler"))
                .andExpect(jsonPath("$.[1]").value("MindSpore"))
                .andExpect(jsonPath("$.[2]").value("openGauss"));
    }

    @Test
    public void queryProductConfigForOpenEuler() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductConfig/%s".formatted(TestConstants.OPENEULER_PRODUCT_TYPE_NAME))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.*", hasSize(4)))
                .andExpect(jsonPath("$.[0].name").value("version"))
                .andExpect(jsonPath("$.[0].label").value("版本号"))
                .andExpect(jsonPath("$.[0].valueType").value("enum([{\"label\":\"openEuler-22.03-LTS\",\"value\":\"openEuler-22.03-LTS\"}])"))
                .andExpect(jsonPath("$.[0].ord").value(1))
                .andExpect(jsonPath("$.[3].name").value("arch"))
                .andExpect(jsonPath("$.[3].label").value("系统架构"))
                .andExpect(jsonPath("$.[3].valueType").value("enum([{\"label\":\"aarch64\",\"value\":\"aarch64\"},{\"label\":\"x86_64\",\"value\":\"x86_64\"}])"))
                .andExpect(jsonPath("$.[3].ord").value(4));
    }

    @Test
    public void queryProductConfigForErrorTypeName() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductConfig/%s".formatted(TestConstants.OPENEULER_PRODUCT_TYPE_NAME.toLowerCase()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.*", hasSize(0)));
    }

    @Test
    public void queryProductByAttrsForOpenEuler1() throws Exception {
        Map<String, String> attributes = CollectionUtils.newHashMap(0);
        attributes.put("version", "openEuler-22.03-LTS");
        attributes.put("imageFormat", "ISO");
        attributes.put("imageType", "everything");
        attributes.put("arch", "x86_64");

        this.mockMvc
                .perform(post("/sbom-api/queryProduct/%s".formatted(TestConstants.OPENEULER_PRODUCT_TYPE_NAME))
                        .content(Mapper.objectMapper.writeValueAsString(attributes))
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)// useless param
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.id").value("55dfefff-ec35-49f4-b395-de3824605bbc"))
                .andExpect(jsonPath("$.name").value("openEuler-22.03-LTS-everything-x86_64-dvd.iso"));
    }

    @Test
    public void queryProductByAttrsForOpenEuler2() throws Exception {
        Map<String, String> attributes = CollectionUtils.newHashMap(0);
        attributes.put("arch", "x86_64");
        attributes.put("imageType", "everything");
        attributes.put("imageFormat", "ISO");
        attributes.put("version", "openEuler-22.03-LTS");

        this.mockMvc
                .perform(post("/sbom-api/queryProduct/%s".formatted(TestConstants.OPENEULER_PRODUCT_TYPE_NAME))
                        .content(Mapper.objectMapper.writeValueAsString(attributes))
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)// useless param
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.id").value("55dfefff-ec35-49f4-b395-de3824605bbc"))
                .andExpect(jsonPath("$.name").value("openEuler-22.03-LTS-everything-x86_64-dvd.iso"));
    }

    @Test
    public void queryProductByAttrsForOpenEulerError() throws Exception {
        Map<String, String> attributes = CollectionUtils.newHashMap(0);
        attributes.put("version", "openEuler-22.03-LTS");
        attributes.put("imageFormat", "ISO");
        attributes.put("imageType", "everything");

        this.mockMvc
                .perform(post("/sbom-api/queryProduct/%s".formatted(TestConstants.OPENEULER_PRODUCT_TYPE_NAME))
                        .content(Mapper.objectMapper.writeValueAsString(attributes))
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("product is not exist"));
    }

    @Test
    public void queryVulnerabilityByPackageId() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryPackageVulnerability/%s".formatted(pkg.getId().toString()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.numberOfElements").value(3))
                .andExpect(jsonPath("$.empty").value(false))
                .andExpect(jsonPath("$.size").value(15))
                .andExpect(jsonPath("$.first").value(true));
    }

    @Test
    public void queryPackageStatisticsByPackageId() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryPackageStatistics/%s".formatted(pkg.getId().toString()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.criticalVulCount").value(0))
                .andExpect(jsonPath("$.highVulCount").value(2))
                .andExpect(jsonPath("$.mediumVulCount").value(2))
                .andExpect(jsonPath("$.lowVulCount").value(0))
                .andExpect(jsonPath("$.noneVulCount").value(0))
                .andExpect(jsonPath("$.unknownVulCount").value(0));
    }

    @Test
    public void queryLicenseAndCopyrightByPackageId() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();
        this.mockMvc
                .perform(get("/sbom-api/queryPackageLicenseAndCopyright/%s".formatted(pkg.getId().toString()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.licenseContent.length()").value(1))
                .andExpect(jsonPath("$.licenseContent.[0].licenseId").value("License-test"))
                .andExpect(jsonPath("$.licenseContent.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.licenseContent.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.licenseContent.[0].legal").value(false))
                .andExpect(jsonPath("$.copyrightContent.length()").value(1))
                .andExpect(jsonPath("$.copyrightContent.[0].organization").value("Free Software Foundation, Inc"))
                .andExpect(jsonPath("$.copyrightContent.[0].startYear").value("1989"))
                .andExpect(jsonPath("$.copyrightContent.[0].additionalInfo").value("Copyright (c) 1989, 1991 Free Software Foundation, Inc."));

    }
}
