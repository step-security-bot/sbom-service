package org.opensourceway.sbom.analyzer;

import org.opensourceway.sbom.model.constants.PublishSbomConstants;
import org.opensourceway.sbom.utils.FileUtil;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.TreeSet;

@Component("definitionFileAnalyzer")
public class DefinitionFileAnalyzer extends AbstractBaseAnalyzer {
    @Override
    protected void extractInputStream(InputStream inputStream, Path workspace) throws IOException {
        FileUtil.extractTarGzipArchive(inputStream, workspace.toString());

        Path defFileTar = Paths.get(workspace.toString(), PublishSbomConstants.DEFINITION_FILE_TAR);
        if (!Files.isRegularFile(defFileTar)) {
            throw new RuntimeException("[%s] doesn't exist or is not a regular file".formatted(
                    PublishSbomConstants.DEFINITION_FILE_TAR));
        }
        FileUtil.extractTarGzipArchive(defFileTar, workspace.toString());
    }

    @Override
    protected TreeSet<CuratedPackage> parsePackages(String productName, Path workspace) throws IOException {
        TreeSet<CuratedPackage> packages = new TreeSet<>();

        Path defFileDir = Paths.get(workspace.toString(), PublishSbomConstants.DEFINITION_FILE_DIR_NAME);
        if (!Files.isDirectory(defFileDir)) {
            throw new RuntimeException("[%s] directory doesn't exist or is not a directory".formatted(
                    PublishSbomConstants.DEFINITION_FILE_DIR_NAME));
        }
        return packages;
    }
}
