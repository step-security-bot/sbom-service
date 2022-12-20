package org.opensourceway.sbom.utils;

import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeBranchInfo;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeFileInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

@SpringBootTest
public class GiteeTest {

    private static final String ARCHIVE_DOWNLOAD_ORG = "src-openeuler";

    private static final String ARCHIVE_DOWNLOAD_REPO = "three-eight-nine-ds-base";

    private static final String ARCHIVE_DOWNLOAD_BRANCH = "openEuler-22.03-LTS";

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Test
    public void downloadRepoArchiveTest() throws IOException {
        Path tmpDirPath = Files.createTempDirectory(TestConstants.ARCHIVE_DOWNLOAD_TMP_DIR_PREFIX);

        Path downloadArchivePath = giteeApi.downloadRepoArchive(tmpDirPath, ARCHIVE_DOWNLOAD_ORG, ARCHIVE_DOWNLOAD_REPO, ARCHIVE_DOWNLOAD_BRANCH);
        File downloadArchiveFile = downloadArchivePath.toFile();
        if (!downloadArchivePath.toFile().exists()) {
            Assertions.fail("failed to download repository archive at temDirPath: %s".formatted(tmpDirPath));
        }
        // 8MB
        Assertions.assertThat(downloadArchiveFile.length() > 8 * 1000 * 1000).isTrue();
        downloadArchiveFile.delete();

        File tmpDir = tmpDirPath.toFile();
        tmpDir.delete();
        if (tmpDir.exists()) {
            Assertions.fail("failed to delete test repository archive temDir: %s".formatted(tmpDirPath));
        }
    }

    @Test
    public void getSingleFileContextTest() {
        List<GiteeFileInfo> fileInfos = (List<GiteeFileInfo>) giteeApi.findRepoFiles(ARCHIVE_DOWNLOAD_ORG,
                ARCHIVE_DOWNLOAD_REPO,
                ARCHIVE_DOWNLOAD_BRANCH,
                SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR,
                SbomRepoConstants.SPEC_FILE_NAME_REGEX);

        Assertions.assertThat(fileInfos.size()).isEqualTo(1);

        Optional<GiteeFileInfo> fileInfoOptional = fileInfos.stream().findFirst();
        Assertions.assertThat(fileInfoOptional.isPresent()).isTrue();
        Assertions.assertThat(fileInfoOptional.get().name()).isEqualTo("389-ds-base.spec");
    }

    @Test
    public void getAllFileContextTest() {
        List<GiteeFileInfo> fileInfos = (List<GiteeFileInfo>) giteeApi.findRepoFiles(ARCHIVE_DOWNLOAD_ORG,
                ARCHIVE_DOWNLOAD_REPO,
                ARCHIVE_DOWNLOAD_BRANCH,
                SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR, null);
        Assertions.assertThat(fileInfos.size()).isEqualTo(12);
        Assertions.assertThat(fileInfos.get(0).name()).isEqualTo("389-ds-base-1.4.3.20.tar.bz2");
        Assertions.assertThat(fileInfos.get(5).name()).isEqualTo("CVE-2021-3514.patch");
        Assertions.assertThat(fileInfos.get(11).name()).isEqualTo("jemalloc.yaml");
    }

    @Test
    public void getMultiFileContextTest() {
        List<GiteeFileInfo> fileInfos = (List<GiteeFileInfo>) giteeApi.findRepoFiles(ARCHIVE_DOWNLOAD_ORG,
                ARCHIVE_DOWNLOAD_REPO,
                ARCHIVE_DOWNLOAD_BRANCH,
                SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR,
                SbomRepoConstants.YAML_FILE_NAME_REGEX);
        Assertions.assertThat(fileInfos.size()).isEqualTo(2);
        Assertions.assertThat(fileInfos.get(0).name()).isEqualTo("389-ds-base.yaml");
        Assertions.assertThat(fileInfos.get(1).name()).isEqualTo("jemalloc.yaml");
    }

    @Test
    public void notFoundFileContextTest() {
        Exception exception = null;
        try {
            giteeApi.findRepoFiles(ARCHIVE_DOWNLOAD_ORG,
                    "openEuler-kernel",
                    ARCHIVE_DOWNLOAD_BRANCH,
                    SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR,
                    SbomRepoConstants.SPEC_FILE_NAME_REGEX);
        } catch (Exception e) {
            exception = e;
        }

        Assertions.assertThat(exception).isNotNull();
        Assertions.assertThat(exception instanceof WebClientResponseException.NotFound).isNotNull();
    }

    @Test
    public void getRepoBranchesTest() {
        List<GiteeBranchInfo.BranchInfo> branchList = (List<GiteeBranchInfo.BranchInfo>) giteeApi.getRepoBranches(ARCHIVE_DOWNLOAD_ORG, ARCHIVE_DOWNLOAD_REPO);

        Optional<GiteeBranchInfo.BranchInfo> branchOptional = branchList.stream()
                .filter(branch -> StringUtils.equalsIgnoreCase(branch.name(), ARCHIVE_DOWNLOAD_BRANCH)).findFirst();

        Assertions.assertThat(branchOptional.isPresent()).isTrue();
        Assertions.assertThat(StringUtils.isNotEmpty(branchOptional.get().commit().sha())).isTrue();
    }

    @Test
    public void getNotExistRepoBranches() {
        Exception exception = null;
        try {
            giteeApi.getRepoBranches(ARCHIVE_DOWNLOAD_ORG, "openEuler-kernel");
        } catch (Exception e) {
            exception = e;
        }

        Assertions.assertThat(exception).isNotNull();
        Assertions.assertThat(exception instanceof WebClientResponseException.NotFound).isNotNull();
    }

}
