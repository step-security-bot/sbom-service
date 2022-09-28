package org.opensourceway.sbom.manager.utils;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.clients.vcs.gitee.model.GiteeFileInfo;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.TestConstants;
import org.opensourceway.sbom.openeuler.obs.SbomRepoConstants;
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
        List<GiteeFileInfo> fileInfos = giteeApi.findRepoFiles(ARCHIVE_DOWNLOAD_ORG,
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
    public void getMultiFileContextTest() {
        List<GiteeFileInfo> fileInfos = giteeApi.findRepoFiles(ARCHIVE_DOWNLOAD_ORG,
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

}
