package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.model.constants.PublishSbomConstants;
import org.opensourceway.sbom.model.enums.SbomContentType;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

public class PublishSbomRequestValidator {
    public static void validate(PublishSbomRequest request) {
        validateParam(request);
        if (SbomContentType.findByType(request.getSbomContentType()).equals(SbomContentType.DEFINITION_FILE)) {
            validateDefinitionFileContent(request);
        }
        if (SbomContentType.findByType(request.getSbomContentType()).equals(SbomContentType.SBOM_TRACER_DATA)) {
            validateSbomTracerDataContent(request);
        }
    }

    private static void validateParam(PublishSbomRequest request) {
        if (!org.springframework.util.StringUtils.hasText(request.getProductName())) {
            throw new RuntimeException("product name is empty");
        }
        if (!org.springframework.util.StringUtils.hasText(request.getSbomContent())) {
            throw new RuntimeException("sbom content is empty");
        }
        if (!org.springframework.util.StringUtils.hasText(request.getSbomContentType())) {
            throw new RuntimeException("sbom content type is empty");
        }
        if (!SbomContentType.isValidType(request.getSbomContentType())) {
            throw new RuntimeException("Invalid sbomContentType: %s, allowed types: %s".formatted(
                    request.getSbomContentType(),
                    Arrays.stream(SbomContentType.values()).map(SbomContentType::getType).toList()));
        }
    }

    private static void validateDefinitionFileContent(PublishSbomRequest request) {
        byte[] bytes = getBase64DecodedContent(request);
        Path tmpDir = createTmpDir(request);
        extractSbomContentTar(bytes, tmpDir.toString());
        validateDefinitionFileTar(tmpDir.toString());
    }

    private static void validateSbomTracerDataContent(PublishSbomRequest request) {
        byte[] bytes = getBase64DecodedContent(request);
        Path tmpDir = createTmpDir(request);
        extractSbomContentTar(bytes, tmpDir.toString());
        validateDefinitionFileTar(tmpDir.toString());
        validateTraceDataTar(tmpDir.toString());
    }

    private static byte[] getBase64DecodedContent(PublishSbomRequest request) {
        try {
            return Base64.getDecoder().decode(request.getSbomContent());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("sbomContent is not a valid base64 encoded string");
        }
    }

    private static Path createTmpDir(PublishSbomRequest request) {
        try {
            return Files.createTempDirectory("ValidateSbomContent-" + request.getProductName().replace("/", "_") + "-");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create temporary directory for sbomContent");
        }
    }

    private static void extractSbomContentTar(byte[] bytes, String dir) {
        try {
            FileUtil.extractTarGzipArchive(new ByteArrayInputStream(bytes), dir);
        } catch (IOException e) {
            throw new RuntimeException("Failed to extract sbomContent tar");
        }
    }

    private static void validateDefinitionFileTar(String dir) {
        Path defFileTar = Paths.get(dir, PublishSbomConstants.DEFINITION_FILE_TAR);
        if (!Files.isRegularFile(defFileTar)) {
            throw new RuntimeException("[%s] doesn't exist or is not a regular file".formatted(
                    PublishSbomConstants.DEFINITION_FILE_TAR));
        }

        try {
            FileUtil.extractTarGzipArchive(defFileTar, dir);
        } catch (IOException e) {
            throw new RuntimeException("Failed to extract [%s]".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
        }

        Path defFileDir = Paths.get(dir, PublishSbomConstants.DEFINITION_FILE_DIR_NAME);
        if (!Files.isDirectory(defFileDir)) {
            throw new RuntimeException("[%s] directory doesn't exist or is not a directory".formatted(
                    PublishSbomConstants.DEFINITION_FILE_DIR_NAME));
        }
    }

    private static void validateTraceDataTar(String dir) {
        Path traceDataTar = Paths.get(dir, PublishSbomConstants.TRACE_DATA_TAR);
        if (!Files.isRegularFile(traceDataTar)) {
            throw new RuntimeException("[%s] doesn't exist or is not a regular file".formatted(
                    PublishSbomConstants.TRACE_DATA_TAR));
        }

        try {
            FileUtil.extractTarGzipArchive(traceDataTar, dir);
        } catch (IOException e) {
            throw new RuntimeException("Failed to extract [%s]".formatted(PublishSbomConstants.TRACE_DATA_TAR));
        }

        Path traceDataDir = Paths.get(dir, PublishSbomConstants.TRACE_DATA_DIR_NAME);
        if (!Files.isDirectory(traceDataDir)) {
            throw new RuntimeException("[%s] directory doesn't exist or is not a directory".formatted(
                    PublishSbomConstants.TRACE_DATA_DIR_NAME));
        }
    }

}

