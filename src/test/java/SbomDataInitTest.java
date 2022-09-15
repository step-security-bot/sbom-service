import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.manager.SbomApplicationContextHolder;
import org.opensourceway.sbom.manager.SbomManagerApplication;
import org.opensourceway.sbom.manager.TestConstants;
import org.opensourceway.sbom.manager.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.ProductStatisticsRepository;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.dao.VulReferenceRepository;
import org.opensourceway.sbom.manager.dao.VulScoreRepository;
import org.opensourceway.sbom.manager.dao.VulnerabilityRepository;
import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.ProductStatistics;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.VulRefSource;
import org.opensourceway.sbom.manager.model.VulReference;
import org.opensourceway.sbom.manager.model.VulScore;
import org.opensourceway.sbom.manager.model.VulScoringSystem;
import org.opensourceway.sbom.manager.model.Vulnerability;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SbomDataInitTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private VulScoreRepository vulScoreRepository;

    @Autowired
    private VulReferenceRepository vulReferenceRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ProductStatisticsRepository productStatisticsRepository;

    @Test
    @Order(1)
    public void uploadSbomFile() throws Exception {
        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME);
        MockMultipartFile file = new MockMultipartFile("uploadFileName", TestConstants.SAMPLE_UPLOAD_FILE_NAME
                , "json", classPathResource.getInputStream());

        this.mockMvc
                .perform(multipart("/sbom-api/uploadSbomFile").file(file)
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(content().string("Success"));
    }

    @Test
    @Order(2)
    public void insertVulnerability() {
        Vulnerability vul_1 = insertVulnerability("CVE-2022-00000-test", "CVE_MANAGER");
        insertVulScore(vul_1, VulScoringSystem.CVSS3.name(), 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

        Vulnerability vul_2 = insertVulnerability("CVE-2022-00001-test", "CVE_MANAGER");
        insertVulScore(vul_2, VulScoringSystem.CVSS2.name(), 9.8, "(AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)");
        insertVulRef(vul_2, VulRefSource.NVD.name(), "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00001-test");

        Vulnerability vul_3 = insertVulnerability("CVE-2022-00000-test", "OSS_INDEX");
        insertVulScore(vul_3, VulScoringSystem.CVSS3.name(), 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
        insertVulScore(vul_3, VulScoringSystem.CVSS2.name(), 7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P");
        insertVulRef(vul_3, VulRefSource.NVD.name(), "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00000-test");
        insertVulRef(vul_3, VulRefSource.OSS_INDEX.name(), "https://ossindex.sonatype.org/vulnerability/sonatype-2022-00000-test");

        Vulnerability vul_4 = insertVulnerability("CVE-2022-00002-test", "OSS_INDEX");
        insertVulRef(vul_4, VulRefSource.NVD.name(), "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-00002-test");
        insertVulRef(vul_4, VulRefSource.GITHUB.name(), "https://github.com/xxx/xxx/security/advisories/xxx");

        Sbom sbom = sbomRepository.findByProductName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        insertExternalVulRef(pkg, vul_1, "pkg:pypi/asttokens@2.0.5");
        insertExternalVulRef(pkg, vul_2, "pkg:pypi/asttokens@2.0.5");
        insertExternalVulRef(pkg, vul_3, "pkg:pypi/asttokens@2.0.5");
        insertExternalVulRef(pkg, vul_4, "pkg:pypi/asttokens@2.0.5");
    }

    private Vulnerability insertVulnerability(String vulId, String source) {
        Vulnerability existVulnerability = vulnerabilityRepository
                .findByVulIdAndSource(vulId, source).orElse(null);
        if (Objects.nonNull(existVulnerability)) {
            vulnerabilityRepository.delete(existVulnerability);
        }

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulId(vulId);
        vulnerability.setType("cve");
        vulnerability.setSource(source);
        return vulnerabilityRepository.save(vulnerability);
    }

    private void insertVulScore(Vulnerability vul, String scoringSystem, Double score, String vector) {
        VulScore vulScore = new VulScore();
        vulScore.setScoringSystem(scoringSystem);
        vulScore.setScore(score);
        vulScore.setVector(vector);
        vulScore.setVulnerability(vul);
        vulScoreRepository.save(vulScore);
    }

    private void insertVulRef(Vulnerability vul, String source, String url) {
        VulReference vulReference = new VulReference();
        vulReference.setSource(source);
        vulReference.setUrl(url);
        vulReference.setVulnerability(vul);
        vulReferenceRepository.save(vulReference);
    }

    private void insertExternalVulRef(Package pkg, Vulnerability vul, String purl) {
        ExternalVulRef externalVulRef = new ExternalVulRef();
        externalVulRef.setPkg(pkg);
        externalVulRef.setVulnerability(vul);
        externalVulRef.setCategory("SECURITY");
        externalVulRef.setType("cve");
        externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(purl));
        externalVulRefRepository.save(externalVulRef);
    }

    @Test
    public void uploadOpenEulerSbomFile() throws Exception {
        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_REPODATA_SBOM_FILE_NAME);
        MockMultipartFile file = new MockMultipartFile("uploadFileName", TestConstants.SAMPLE_REPODATA_SBOM_FILE_NAME
                , "json", classPathResource.getInputStream());

        this.mockMvc
                .perform(multipart("/sbom-api/uploadSbomFile").file(file)
                        .param("productName", TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(content().string("Success"));
    }

    @Test
    @Order(3)
    public void insertProductStatistics() {
        Product product = productRepository.findByName(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(product).isNotNull();
        ProductStatistics statistics = productStatisticsRepository
                .findByProductNameAndCreateTime(TestConstants.SAMPLE_PRODUCT_NAME, new Timestamp((1663150600000L)))
                .orElse(new ProductStatistics());
        statistics.setProduct(product);
        statistics.setCreateTime(new Timestamp((1663150600000L)));
        statistics.setPackageCount(100L);
        statistics.setDepCount(200L);
        statistics.setModuleCount(300L);
        statistics.setRuntimeDepCount(0L);
        statistics.setVulCount(50L);
        statistics.setLicenseCount(60L);
        statistics.setCriticalVulCount(7L);
        statistics.setHighVulCount(8L);
        statistics.setMediumVulCount(9L);
        statistics.setLowVulCount(10L);
        statistics.setNoneVulCount(11L);
        statistics.setUnknownVulCount(5L);
        statistics.setPackageWithCriticalVulCount(13L);
        statistics.setPackageWithHighVulCount(14L);
        statistics.setPackageWithMediumVulCount(15L);
        statistics.setPackageWithLowVulCount(16L);
        statistics.setPackageWithNoneVulCount(17L);
        statistics.setPackageWithUnknownVulCount(18L);
        statistics.setPackageWithoutVulCount(7L);
        statistics.setPackageWithLegalLicenseCount(20L);
        statistics.setPackageWithIllegalLicenseCount(21L);
        statistics.setPackageWithoutLicenseCount(19L);
        statistics.setPackageWithMultiLicenseCount(10L);
        statistics.setLicenseDistribution(Map.of("Apache-2.0", 2L));

        ProductStatistics anotherStatistics = productStatisticsRepository
                .findByProductNameAndCreateTime(TestConstants.SAMPLE_PRODUCT_NAME, new Timestamp((1663250600000L)))
                .orElse(new ProductStatistics());
        anotherStatistics.setProduct(product);
        anotherStatistics.setCreateTime(new Timestamp((1663250600000L)));
        anotherStatistics.setPackageCount(1000L);
        anotherStatistics.setDepCount(2000L);
        anotherStatistics.setModuleCount(3000L);
        anotherStatistics.setRuntimeDepCount(0L);
        anotherStatistics.setVulCount(500L);
        anotherStatistics.setLicenseCount(600L);
        anotherStatistics.setCriticalVulCount(70L);
        anotherStatistics.setHighVulCount(80L);
        anotherStatistics.setMediumVulCount(90L);
        anotherStatistics.setLowVulCount(100L);
        anotherStatistics.setNoneVulCount(110L);
        anotherStatistics.setUnknownVulCount(50L);
        anotherStatistics.setPackageWithCriticalVulCount(130L);
        anotherStatistics.setPackageWithHighVulCount(140L);
        anotherStatistics.setPackageWithMediumVulCount(150L);
        anotherStatistics.setPackageWithLowVulCount(160L);
        anotherStatistics.setPackageWithNoneVulCount(170L);
        anotherStatistics.setPackageWithUnknownVulCount(180L);
        anotherStatistics.setPackageWithoutVulCount(70L);
        anotherStatistics.setPackageWithLegalLicenseCount(200L);
        anotherStatistics.setPackageWithIllegalLicenseCount(210L);
        anotherStatistics.setPackageWithoutLicenseCount(190L);
        anotherStatistics.setPackageWithMultiLicenseCount(100L);
        anotherStatistics.setLicenseDistribution(Map.of("MIT", 20L));

        product.setProductStatistics(List.of(statistics, anotherStatistics));
        productRepository.save(product);
    }
}
