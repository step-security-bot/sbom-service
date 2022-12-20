package org.opensourceway.sbom.model;

import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.enums.SbomFileType;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class FileObjectTest {

    private static final String TEST_SBOM_ID = "a428941e-0715-4ada-9549-0908cfbb00e4";

    private static final String TEST_SPDX_ID = "1111";

    private static final String TEST_FILE_NAME = "1111";

    @Test
    public void fileCompareWithSbomTest() {
        File file1 = new File();
        Sbom sbom1 = new Sbom();
        sbom1.setId(UUID.fromString(TEST_SBOM_ID));
        file1.setSbom(sbom1);
        file1.setSpdxId(TEST_SPDX_ID);
        file1.setFileName(TEST_FILE_NAME);
        file1.setFileTypes(new String[]{SbomFileType.SOURCE.name()});


        File file2 = new File();
        Sbom sbom2 = new Sbom();
        sbom2.setId(UUID.fromString(TEST_SBOM_ID));
        file2.setSbom(sbom2);
        file2.setSpdxId(TEST_SPDX_ID);
        file2.setFileName(TEST_FILE_NAME);
        file2.setFileTypes(new String[]{SbomFileType.SOURCE.name()});

        assertThat(file1).isEqualTo(file2);

        List<File> fileList = new ArrayList<>();
        fileList.add(file1);
        fileList.add(file2);

        assertThat(fileList.size()).isEqualTo(2);
        assertThat(fileList.stream().distinct().toList().size()).isEqualTo(1);
    }

    @Test
    public void fileCompareWithoutSbomTest() {
        File file1 = new File();
        file1.setSpdxId(TEST_SPDX_ID);
        file1.setFileName(TEST_FILE_NAME);
        file1.setFileTypes(new String[]{SbomFileType.SOURCE.name()});


        File file2 = new File();
        file2.setSpdxId(TEST_SPDX_ID);
        file2.setFileName(TEST_FILE_NAME);
        file2.setFileTypes(new String[]{SbomFileType.SOURCE.name()});

        assertThat(file1).isEqualTo(file2);

        List<File> fileList = new ArrayList<>();
        fileList.add(file1);
        fileList.add(file2);

        assertThat(fileList.size()).isEqualTo(2);
        assertThat(fileList.stream().distinct().toList().size()).isEqualTo(1);
    }

}
