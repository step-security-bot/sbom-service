import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.openeuler.sbom.manager.SbomApplicationContextHolder;
import org.openeuler.sbom.manager.SbomManagerApplication;
import org.openeuler.sbom.manager.TestConstants;
import org.openeuler.sbom.manager.dao.ExternalVulRefRepository;
import org.openeuler.sbom.manager.dao.SbomRepository;
import org.openeuler.sbom.manager.dao.VulReferenceRepository;
import org.openeuler.sbom.manager.dao.VulScoreRepository;
import org.openeuler.sbom.manager.dao.VulnerabilityRepository;
import org.openeuler.sbom.manager.model.ExternalVulRef;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.Sbom;
import org.openeuler.sbom.manager.model.VulRefSource;
import org.openeuler.sbom.manager.model.VulReference;
import org.openeuler.sbom.manager.model.VulScore;
import org.openeuler.sbom.manager.model.VulScoringSystem;
import org.openeuler.sbom.manager.model.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

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
    public void insertVulnerability() throws Exception {
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

        Sbom sbom = sbomRepository.findByProductId(TestConstants.SAMPLE_PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        Package pkg = sbom.getPackages().stream()
                .filter(it -> StringUtils.equals(it.getSpdxId(), "SPDXRef-Package-PyPI-asttokens-2.0.5"))
                .findFirst().orElse(null);
        assertThat(pkg).isNotNull();

        insertExternalVulRef(pkg, vul_1);
        insertExternalVulRef(pkg, vul_2);
        insertExternalVulRef(pkg, vul_3);
        insertExternalVulRef(pkg, vul_4);
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

    private void insertExternalVulRef(Package pkg, Vulnerability vul) {
        ExternalVulRef externalVulRef = new ExternalVulRef();
        externalVulRef.setPkg(pkg);
        externalVulRef.setVulnerability(vul);
        externalVulRef.setCategory("SECURITY");
        externalVulRef.setType("cve");
        externalVulRefRepository.save(externalVulRef);
    }

    // TODO 新增openEuler everything镜像的SBOM导入（SBOM需裁剪，否则过大）
}
