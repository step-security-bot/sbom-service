package org.opensourceway.sbom.controller;


import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.SbomManagerApplication;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.api.sbom.SbomService;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageWithStatisticsVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.utils.JsonContainsMatcher;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
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

    @Autowired
    private ProductRepository productRepository;

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
                .andExpect(jsonPath("$.totalElements").value(76))
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
                .andExpect(jsonPath("$.externalList.*", hasSize(216)))
                .andExpect(jsonPath("$.relationshipList.*", hasSize(4)));
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
                .andExpect(jsonPath("$.externalList.*", hasSize(0)))
                .andExpect(jsonPath("$.relationshipList.*", hasSize(0)));
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
                .andExpect(jsonPath("$.externalList.*", hasSize(216)))
                .andExpect(jsonPath("$.relationshipList.*", hasSize(0)));
    }

    @Test
    public void queryRelationshipRef() throws Exception {
        if (PkgQueryControllerTests.packageId == null) {
            getPackageId();
        }
        this.mockMvc
                .perform(get("/sbom-api/queryPackageBinaryManagement/%s/%s".formatted(PkgQueryControllerTests.packageId, ReferenceCategory.RELATIONSHIP_MANAGER.name()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.packageList.*", hasSize(0)))
                .andExpect(jsonPath("$.provideList.*", hasSize(0)))
                .andExpect(jsonPath("$.externalList.*", hasSize(0)))
                .andExpect(jsonPath("$.relationshipList.*", hasSize(4)));
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
                .andExpect(jsonPath("$.size").value(15))
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
                .andExpect(jsonPath("$.size").value(15));
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
                .andExpect(jsonPath("$.size").value(15))
                .andExpect(jsonPath("$.content.[0].name").value("hive"));
    }

    @Test
    public void queryPackageInfoByRuntimeDepTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.RELATIONSHIP_MANAGER.name())
                        .param("type", "rpm")
                        .param("namespace", "")
                        .param("name", "hive")
                        .param("version", "3.1.2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.size").value(15))
                .andExpect(jsonPath("$.content.[0].name").value("hadoop-3.1-common"))
                .andExpect(jsonPath("$.content.[1].name").value("spark"))
                .andExpect(jsonPath("$.content.[2].name").value("storm"));
    }

    @Test
    public void queryPackageInfoByRuntimeDepNoVersionTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.RELATIONSHIP_MANAGER.name())
                        .param("type", "rpm")
                        .param("namespace", "")
                        .param("name", "hive")
                        .param("version", "3.1.2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.size").value(15))
                .andExpect(jsonPath("$.content.[0].name").value("hadoop-3.1-common"))
                .andExpect(jsonPath("$.content.[1].name").value("spark"))
                .andExpect(jsonPath("$.content.[2].name").value("storm"));
    }

    @Test
    public void queryPackageInfoByRuntimeDepErrorVersionTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.RELATIONSHIP_MANAGER.name())
                        .param("type", "rpm")
                        .param("namespace", "")
                        .param("name", "hive")
                        .param("version", "3.1.3")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.totalPages").value(0))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.size").value(15));
    }

    @Test
    public void queryPackageInfoByRuntimeDepWithPageTest() throws Exception {
        this.mockMvc
                .perform(post("/sbom-api/querySbomPackagesByBinary")
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .param("binaryType", ReferenceCategory.RELATIONSHIP_MANAGER.name())
                        .param("type", "rpm")
                        .param("namespace", "")
                        .param("name", "hive")
                        .param("version", "3.1.2")
                        .param("page", "1")
                        .param("size", "1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(false))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(3))
                .andExpect(jsonPath("$.number").value(1))
                .andExpect(jsonPath("$.size").value(1))
                .andExpect(jsonPath("$.content.[0].name").value("spark"));
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
                .andExpect(jsonPath("$.*", hasSize(5)));
    }

    @Test
    public void queryProductConfigForOpenEuler() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductConfig/%s".formatted(TestConstants.TEST_PRODUCT_TYPE))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.*", hasSize(4)))
                .andExpect(jsonPath("$.name").value("arg"))
                .andExpect(jsonPath("$.label").value("测试参数"));
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
                .andExpect(jsonPath("$.name").isEmpty())
                .andExpect(jsonPath("$.label").isEmpty())
                .andExpect(jsonPath("$.valueToNextConfig").isEmpty());
    }

    @Test
    public void queryProductByAttrsForOpenEuler1() throws Exception {
        Map<String, String> attributes = CollectionUtils.newHashMap(0);
        attributes.put("version", "openEuler-22.03-LTS");
        attributes.put("imageFormat", "ISO");
        attributes.put("imageType", "Everything");
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
        attributes.put("imageType", "Everything");
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
                .perform(get("/sbom-api/queryVulnerability/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME))
                        .param("packageId", pkg.getId().toString())
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
    public void queryVulnerabilityByProductName() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryVulnerability/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME))
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
    public void queryVulnerabilityByProductNameAndHighSeverity() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryVulnerability/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME))
                        .param("severity", CvssSeverity.HIGH.name())
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.last").value(true))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.totalPages").value(1))
                .andExpect(jsonPath("$.number").value(0))
                .andExpect(jsonPath("$.numberOfElements").value(1))
                .andExpect(jsonPath("$.empty").value(false))
                .andExpect(jsonPath("$.size").value(15))
                .andExpect(jsonPath("$.first").value(true));
    }

    @Test
    public void queryVulnerabilityByProductNameAndLowSeverity() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryVulnerability/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME))
                        .param("severity", CvssSeverity.LOW.name())
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
                .andExpect(jsonPath("$.empty").value(true))
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
                .andExpect(jsonPath("$.highVulCount").value(1))
                .andExpect(jsonPath("$.mediumVulCount").value(1))
                .andExpect(jsonPath("$.lowVulCount").value(0))
                .andExpect(jsonPath("$.noneVulCount").value(0))
                .andExpect(jsonPath("$.unknownVulCount").value(1));
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
                .andExpect(jsonPath("$.licenseContent.length()").value(2))
                .andExpect(jsonPath("$.licenseContent.[0].licenseId").value("License-test"))
                .andExpect(jsonPath("$.licenseContent.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.licenseContent.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.licenseContent.[0].legal").value(false))
                .andExpect(jsonPath("$.copyrightContent.length()").value(1))
                .andExpect(jsonPath("$.copyrightContent.[0].organization").value("Free Software Foundation, Inc"))
                .andExpect(jsonPath("$.copyrightContent.[0].startYear").value("1989"))
                .andExpect(jsonPath("$.copyrightContent.[0].additionalInfo").value("Copyright (c) 1989, 1991 Free Software Foundation, Inc."));

    }

    @Test
    public void queryLicenseUniversal() throws Exception {
        Product product = productRepository.findByName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(product).isNotNull();
        this.mockMvc
                .perform(get("/sbom-api/queryLicenseUniversalApi/")
                        .param("productName", product.getName())
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.content.[0].licenseId").value("License-test"))
                .andExpect(jsonPath("$.content.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[0].legal").value(false))
                .andExpect(jsonPath("$.content.[1].licenseId").value("License-test1"))
                .andExpect(jsonPath("$.content.[1].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[1].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[1].legal").value(true));

        this.mockMvc
                .perform(get("/sbom-api/queryLicenseUniversalApi/")
                        .param("productName", product.getName())
                        .param("orderBy", "count")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.content.[0].licenseId").value("License-test1"))
                .andExpect(jsonPath("$.content.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[0].legal").value(true))
                .andExpect(jsonPath("$.content.[1].licenseId").value("License-test"))
                .andExpect(jsonPath("$.content.[1].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[1].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[1].legal").value(false));

        this.mockMvc
                .perform(get("/sbom-api/queryLicenseUniversalApi/")
                        .param("productName", product.getName())
                        .param("license", "License-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content.[0].licenseId").value("License-test"))
                .andExpect(jsonPath("$.content.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[0].legal").value(false));

        this.mockMvc
                .perform(get("/sbom-api/queryLicenseUniversalApi/")
                        .param("productName", product.getName())
                        .param("isLegal", "true")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content.[0].licenseId").value("License-test1"))
                .andExpect(jsonPath("$.content.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[0].legal").value(true));

        this.mockMvc
                .perform(get("/sbom-api/queryLicenseUniversalApi/")
                        .param("productName", product.getName())
                        .param("license", "License-test1")
                        .param("isLegal", "true")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.content.[0].licenseId").value("License-test1"))
                .andExpect(jsonPath("$.content.[0].licenseName").value("License for test"))
                .andExpect(jsonPath("$.content.[0].licenseUrl").value("https://xxx/licenses/License-test"))
                .andExpect(jsonPath("$.content.[0].legal").value(true));

    }

    @Test
    public void queryVulImpact() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryVulImpact/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME))
                        .param("vulId", "CVE-2022-00000-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.nodes.length()").value(2))
                .andExpect(jsonPath("$.nodes.[0].nodeType").value("package"))
                .andExpect(jsonPath("$.nodes.[0].label").value("pkg:pypi/asttokens@2.0.5"))
                .andExpect(jsonPath("$.nodes.[0].x").value(0.0))
                .andExpect(jsonPath("$.nodes.[0].y").value(0.0))
                .andExpect(jsonPath("$.nodes.[0].id").value("1"))
                .andExpect(jsonPath("$.nodes.[0].elementId").isNotEmpty())
                .andExpect(jsonPath("$.nodes.[0].size").value(30.0))
                .andExpect(jsonPath("$.nodes.[1].nodeType").value("vulnerability"))
                .andExpect(jsonPath("$.nodes.[1].label").value("CVE-2022-00000-test"))
                .andExpect(jsonPath("$.nodes.[1].x").value(0.0))
                .andExpect(jsonPath("$.nodes.[1].y").value(-2000.0))
                .andExpect(jsonPath("$.nodes.[1].id").value("0"))
                .andExpect(jsonPath("$.nodes.[1].size").value(50.0))
                .andExpect(jsonPath("$.nodes.[1].elementId").isEmpty())
                .andExpect(jsonPath("$.edges.length()").value(1))
                .andExpect(jsonPath("$.edges.[0].sourceID").value("0"))
                .andExpect(jsonPath("$.edges.[0].targetID").value("1"))
                .andExpect(jsonPath("$.edges.[0].size").value(1.0));
    }

    @Test
    public void queryVulImpactNotExistVul() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryVulImpact/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME))
                        .param("vulId", "CVE-NOT-EXISTS")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.nodes.length()").value(0))
                .andExpect(jsonPath("$.edges.length()").value(0));
    }

    @Test
    public void queryVulImpactNotExistProduct() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryVulImpact/%s".formatted(TestConstants.SAMPLE_PRODUCT_NAME + "error"))
                        .param("vulId", "CVE-2022-00000-test")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.nodes.length()").value(0))
                .andExpect(jsonPath("$.edges.length()").value(0));
    }

    @Test
    public void queryPackageVulnerability() throws Exception {
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
    public void queryUpstreamSuccess() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-rpm-hive-3.1.2"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryUpstreamAndPatchInfo/%s".formatted(pkg.getId().toString()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.upstreamList", hasSize(2)))
                .andExpect(jsonPath("$.patchList", hasSize(3)))
                .andExpect(jsonPath("$.upstreamList.[0].url").value("http://hive.apache.org/"))
                .andExpect(jsonPath("$.patchList.[1].url").value("https://gitee.com/src-openeuler/hive/blob/openEuler-22.03-LTS/test2.patch"));
    }

    @Test
    public void queryUpstreamForEmpty() throws Exception {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-rpm-spark-3.2.0"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        this.mockMvc
                .perform(get("/sbom-api/queryUpstreamAndPatchInfo/%s".formatted(pkg.getId().toString()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.upstreamList", hasSize(0)))
                .andExpect(jsonPath("$.patchList", hasSize(0)));
    }

    @Test
    public void queryUpstreamForNoPackage() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryUpstreamAndPatchInfo/%s".formatted("316ff894-e58f-4f19-ad14-de5a7fb9f711"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.upstreamList", hasSize(0)))
                .andExpect(jsonPath("$.patchList", hasSize(0)));
    }
}
