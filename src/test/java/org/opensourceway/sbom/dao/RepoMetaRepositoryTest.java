package org.opensourceway.sbom.dao;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RepoMetaRepositoryTest {

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Test
    @Order(0)
    public void clearRepoMetaTest() {
        List<RepoMeta> deleteIds = repoMetaRepository.deleteByProductType(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME);
        System.out.printf("delete %s's old data size:%s%n", SbomConstants.PRODUCT_OPENEULER_NAME, deleteIds == null ? 0 : deleteIds.size());
    }

    @Test
    @Order(1)
    public void insertRepoMetaTest() {
        RepoMeta repoMeta = new RepoMeta();
        repoMeta.setProductType(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME);
        repoMeta.setRepoName("three-eight-nine-ds-base");
        repoMeta.setBranch("openEuler-22.03-LTS");
        repoMeta.setSpecDownloadUrl("https://gitee.com/src-openeuler/three-eight-nine-ds-base/raw/openEuler-22.03-LTS/389-ds-base.spec");
        repoMeta.setUpstreamDownloadUrls(new String[]{
                "https://gitee.com/src-openeuler/three-eight-nine-ds-base/raw/openEuler-22.03-LTS/389-ds-base.yaml",
                "https://gitee.com/src-openeuler/three-eight-nine-ds-base/raw/openEuler-22.03-LTS/jemalloc.yaml"});
        repoMeta.setPatchInfo(new String[]{"CVE-2021-3652.patch", "CVE-2021-3514.patch", "Fix-attributeError-type-object-build_manpages.patch"});
        repoMeta.setPackageNames(new String[]{"389-ds-base",
                "389-ds-base-devel",
                "389-ds-base-help",
                "389-ds-base-legacy-tools",
                "389-ds-base-snmp",
                "cockpit-389-ds",
                "python3-lib389"});
        repoMetaRepository.save(repoMeta);
    }

    @Test
    @Order(2)
    public void insertRepoMetaDuplicateTest() {
        Exception exception = null;
        try {
            RepoMeta repoMeta = new RepoMeta();
            repoMeta.setProductType(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME);
            repoMeta.setRepoName("three-eight-nine-ds-base");
            repoMeta.setBranch("openEuler-22.03-LTS");
            repoMetaRepository.save(repoMeta);
        } catch (Exception e) {
            exception = e;

        }
        assertThat(exception).isNotNull();
        Throwable innerException = exception.getCause().getCause();
        assertThat(innerException instanceof PSQLException).isTrue();
        assertThat(((PSQLException) innerException).getSQLState()).isEqualTo("23505");
    }

    @Test
    @Order(3)
    public void selectRepoMetaDuplicateTest() {
        Optional<RepoMeta> repoMetaOptional = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                "three-eight-nine-ds-base",
                "openEuler-22.03-LTS");
        assertThat(repoMetaOptional.isPresent()).isTrue();

        RepoMeta repoMeta = repoMetaOptional.get();
        assertThat(repoMeta.getSpecDownloadUrl()).isNotNull();
        assertThat(repoMeta.getPackageNames().length).isEqualTo(7);
        assertThat(repoMeta.getPackageNames()[1]).isEqualTo("389-ds-base-devel");
        assertThat(repoMeta.getPackageNames()[3]).isEqualTo("389-ds-base-legacy-tools");
        assertThat(repoMeta.getUpstreamDownloadUrls().length).isEqualTo(2);
        assertThat(StringUtils.contains(repoMeta.getUpstreamDownloadUrls()[0], "389-ds-base.yaml")).isTrue();
        assertThat(repoMeta.getPatchInfo().length).isEqualTo(3);
        assertThat(repoMeta.getPatchInfo()[0]).isEqualTo("CVE-2021-3652.patch");
        assertThat(repoMeta.getPatchInfo()[2]).isEqualTo("Fix-attributeError-type-object-build_manpages.patch");
    }

    @Test
    @Order(4)
    public void selectRepoMetaByPackageNameTest() {
        List<RepoMeta> repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME, "openEuler-22.03-LTS",
                "389-ds-base");
        assertThat(CollectionUtils.isNotEmpty(repoMetaList)).isTrue();

        repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME, "openEuler-22.03-LTS",
                "389-ds-base-devel");
        assertThat(CollectionUtils.isNotEmpty(repoMetaList)).isTrue();

        repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME, "openEuler-22.03-LTS",
                "389-ds-base-XXX");
        assertThat(CollectionUtils.isNotEmpty(repoMetaList)).isFalse();
    }

    @Test
    @Order(5)
    public void deleteRepoMetaTest() {
        Optional<RepoMeta> repoMetaOptional = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                "three-eight-nine-ds-base",
                "openEuler-22.03-LTS");

        assertThat(repoMetaOptional.isPresent()).isTrue();
        repoMetaRepository.delete(repoMetaOptional.get());

        repoMetaOptional = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME,
                "three-eight-nine-ds-base",
                "openEuler-22.03-LTS");
        assertThat(repoMetaOptional.isPresent()).isFalse();
    }

}
