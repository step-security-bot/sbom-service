package org.opensourceway.sbom.service;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.api.repo.RepoMetaParser;
import org.opensourceway.sbom.api.repo.RepoService;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class RepoServiceTest {
    @Autowired
    private RepoService repoService;

    @Autowired
    private RepoMetaParser repoMetaParser;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Test
    @Order(0)
    public void clearRepoMetaTest() {
        List<RepoMeta> existData = repoMetaRepository.findByProductType(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        repoMetaRepository.deleteAllInBatch(existData);
    }

    @Test
    @Order(1)
    public void fetchRepoMetaTest() {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();
        repoInfoSet.add(new RepoInfoVo("three-eight-nine-ds-base", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("CUnit", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("texlive-split-m", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("openEuler-kernel", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("kata_integration", "openEuler-22.03-LTS"));
        repoInfoSet.add(new RepoInfoVo("kata-containers", "openEuler-22.03-LTS"));

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaParser.fetchRepoBuildFileInfo(repoInfo);
            repoMetaParser.fetchRepoPackageAndPatchInfo(repoInfo);
        }

        List<RepoMeta> deleteIds = repoMetaRepository.deleteByProductType(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        System.out.printf("delete %s's old data size:%s%n", SbomConstants.PRODUCT_OPENEULER_NAME, deleteIds == null ? 0 : deleteIds.size());

        for (RepoInfoVo repoInfo : repoInfoSet) {
            repoMetaRepository.save(RepoMeta.fromRepoInfoVo(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME, repoInfo));
        }


        assertThat(repoInfoSet.size()).isEqualTo(6);

        List<RepoInfoVo> repoInfoList = repoInfoSet.stream().toList();
        assertThat(repoInfoList.get(0).getPatchInfo().get(0)).isEqualTo("CVE-2021-3652.patch");
        assertThat(repoInfoList.get(0).getPatchInfo().get(2)).isEqualTo("Fix-attributeError-type-object-build_manpages.patch");
        assertThat(repoInfoList.get(0).getPackageNames().get(0)).isEqualTo("389-ds-base");
        assertThat(repoInfoList.get(0).getPackageNames().get(3)).isEqualTo("389-ds-base-snmp");
        assertThat(repoInfoList.get(0).getPackageNames().get(4)).isEqualTo("python3-lib389");

        assertThat(repoInfoList.get(1).getPatchInfo()).isNull();
        assertThat(repoInfoList.get(1).getPackageNames().size()).isEqualTo(3);

        assertThat(repoInfoList.get(2).getPackageNames().size()).isEqualTo(140);

        assertThat(repoInfoList.get(3).getLastCommitId()).isNull();
        assertThat(repoInfoList.get(3).getDownloadLocation()).isNull();
        assertThat(repoInfoList.get(3).getSpecDownloadUrl()).isNull();
        assertThat(repoInfoList.get(3).getUpstreamDownloadUrls()).isNull();
        assertThat(repoInfoList.get(3).getPatchInfo()).isNull();
        assertThat(repoInfoList.get(3).getPackageNames()).isNull();

        // clear data
        deleteIds = repoMetaRepository.deleteByProductType(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        System.out.printf("delete %s's old data size:%s%n", SbomConstants.PRODUCT_OPENEULER_NAME, deleteIds == null ? 0 : deleteIds.size());
    }

    @Test
    @Order(2)
    @Disabled
    public void fetchOpenEulerRepoMetaTest() throws IOException {
        long start = System.currentTimeMillis();
        Set<RepoInfoVo> result = repoService.fetchOpenEulerRepoMeta();
        System.out.printf("fetchOpenEulerRepoMetaTest coast:%d, repoSet size:%d%n", (System.currentTimeMillis() - start), result.size());
    }

}
