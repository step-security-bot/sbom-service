package org.opensourceway.sbom.analyzer;

import org.opensourceway.sbom.analyzer.parser.CollectedInfoParser;
import org.opensourceway.sbom.analyzer.parser.Http2Parser;
import org.opensourceway.sbom.analyzer.parser.HttpParser;
import org.opensourceway.sbom.analyzer.parser.ProcessParser;
import org.opensourceway.sbom.model.constants.PublishSbomConstants;
import org.opensourceway.sbom.model.pojo.vo.analyzer.ProcessIdentifier;
import org.opensourceway.sbom.utils.FileUtil;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

@Component("traceDataAnalyzer")
public class TraceDataAnalyzer extends AbstractBaseAnalyzer {
    @Autowired
    private ProcessParser processParser;

    @Autowired
    private HttpParser httpParser;

    @Autowired
    private Http2Parser http2Parser;

    @Autowired
    private CollectedInfoParser collectedInfoParser;

    @Override
    protected void extractInputStream(InputStream inputStream, Path workspace) throws IOException {
        FileUtil.extractTarGzipArchive(inputStream, workspace.toString());
        FileUtil.extractTarGzipArchive(Paths.get(workspace.toString(), PublishSbomConstants.TRACE_DATA_TAR), workspace.toString());
        FileUtil.extractTarGzipArchive(Paths.get(workspace.toString(), PublishSbomConstants.DEFINITION_FILE_TAR), workspace.toString());
    }

    @Override
    protected TreeSet<CuratedPackage> parsePackages(String productName, Path workspace) throws IOException {
        Path traceDataPath = Paths.get(workspace.toString(), PublishSbomConstants.TRACE_DATA_DIR_NAME);
        List<ProcessIdentifier> allProcess = processParser.getAllProcess(traceDataPath);
        Set<CuratedPackage> httpPackages = httpParser.parse(traceDataPath, allProcess);
        Set<CuratedPackage> http2Packages = http2Parser.parse(traceDataPath, allProcess);
        Set<CuratedPackage> otherPackages = collectedInfoParser.parse(traceDataPath, allProcess);
        TreeSet<CuratedPackage> packages = new TreeSet<>();
        for (Set<CuratedPackage> curatedPackages : Arrays.asList(httpPackages, http2Packages, otherPackages)) {
            packages.addAll(curatedPackages);
        }
        return packages;
    }
}
