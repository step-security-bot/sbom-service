package org.opensourceway.sbom.manager.utils;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.manager.TestConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

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

}
