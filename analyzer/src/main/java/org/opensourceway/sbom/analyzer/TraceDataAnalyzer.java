package org.opensourceway.sbom.analyzer;

import org.apache.commons.io.FileUtils;
import org.opensourceway.sbom.analyzer.model.ProcessIdentifier;
import org.opensourceway.sbom.analyzer.parser.CollectedInfoParser;
import org.opensourceway.sbom.analyzer.parser.Http2Parser;
import org.opensourceway.sbom.analyzer.parser.HttpParser;
import org.opensourceway.sbom.analyzer.parser.ProcessParser;
import org.opensourceway.sbom.constants.PublishSbomConstants;
import org.opensourceway.sbom.utils.FileUtil;
import org.opensourceway.sbom.utils.Mapper;
import org.ossreviewtoolkit.analyzer.Analyzer;
import org.ossreviewtoolkit.analyzer.PackageCurationProvider;
import org.ossreviewtoolkit.analyzer.PackageManager;
import org.ossreviewtoolkit.model.AnalyzerResult;
import org.ossreviewtoolkit.model.AnalyzerRun;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.ossreviewtoolkit.model.DependencyGraph;
import org.ossreviewtoolkit.model.DependencyGraphNode;
import org.ossreviewtoolkit.model.Identifier;
import org.ossreviewtoolkit.model.OrtResult;
import org.ossreviewtoolkit.model.PackageLinkage;
import org.ossreviewtoolkit.model.Project;
import org.ossreviewtoolkit.model.Repository;
import org.ossreviewtoolkit.model.RootDependencyIndex;
import org.ossreviewtoolkit.model.VcsInfo;
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration;
import org.ossreviewtoolkit.model.config.CopyrightGarbage;
import org.ossreviewtoolkit.model.config.LicenseFilenamePatterns;
import org.ossreviewtoolkit.model.config.RepositoryConfiguration;
import org.ossreviewtoolkit.model.licenses.DefaultLicenseInfoProvider;
import org.ossreviewtoolkit.model.licenses.LicenseInfoResolver;
import org.ossreviewtoolkit.model.utils.SimplePackageConfigurationProvider;
import org.ossreviewtoolkit.reporter.DefaultLicenseTextProvider;
import org.ossreviewtoolkit.reporter.reporters.spdx.SpdxDocumentModelMapper;
import org.ossreviewtoolkit.utils.ort.Environment;
import org.ossreviewtoolkit.utils.ort.ProcessedDeclaredLicense;
import org.ossreviewtoolkit.utils.spdx.model.SpdxDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Component
public class TraceDataAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(TraceDataAnalyzer.class);

    @Autowired
    private ProcessParser processParser;

    @Autowired
    private HttpParser httpParser;

    @Autowired
    private Http2Parser http2Parser;

    @Autowired
    private CollectedInfoParser collectedInfoParser;

    private static final String RESULT_FILE = "trace_result.json";

    private static final String PROJECT_MANAGER_TYPE = "Tracer";

    private static final String PROJECT_NAME = "Git";

    private static final String PROJECT_SCOPE = "compile";

    public byte[] analyze(String productName, InputStream inputStream) {
        Path workspace = null;
        try {
            logger.info("start to analyze {}", productName);

            workspace = Files.createTempDirectory(PROJECT_MANAGER_TYPE + "-" + productName + "-");

            parseTraceData(inputStream, workspace);
            OrtResult ortResult = ortAnalyze(workspace);
            SpdxDocument spdxDocument = ortSpdxReport(ortResult, productName);
            byte[] sbomBytes = Mapper.jsonSbomMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(spdxDocument);

            logger.info("successfully analyzed {}", productName);
            return sbomBytes;
        } catch (IOException e) {
            logger.error("failed to analyze {}", productName, e);
            throw new RuntimeException(e);
        } finally {
            if (Objects.nonNull(workspace)) {
                FileUtils.deleteQuietly(workspace.toFile());
            }
        }
    }

    private void parseTraceData(InputStream inputStream, Path workspace) throws IOException {
        logger.info("start to parse trace data");

        FileUtil.extractTarGzipArchive(inputStream, workspace.toString());
        FileUtil.extractTarGzipArchive(Paths.get(workspace.toString(), PublishSbomConstants.TRACE_DATA_TAR), workspace.toString());
        FileUtil.extractTarGzipArchive(Paths.get(workspace.toString(), PublishSbomConstants.DEFINITION_FILE_TAR), workspace.toString());

        Path traceDataPath = Paths.get(workspace.toString(), PublishSbomConstants.TRACE_DATA_DIR_NAME);
        List<ProcessIdentifier> allProcess = processParser.getAllProcess(traceDataPath, getTaskId(traceDataPath));
        Set<CuratedPackage> httpPackages = httpParser.parse(traceDataPath, allProcess);
        Set<CuratedPackage> http2Packages = http2Parser.parse(traceDataPath, allProcess);
        Set<CuratedPackage> otherPackages = collectedInfoParser.parse(traceDataPath, allProcess);
        TreeSet<CuratedPackage> packages = new TreeSet<>();
        for (Set<CuratedPackage> curatedPackages : Arrays.asList(httpPackages, http2Packages, otherPackages)) {
            packages.addAll(curatedPackages);
        }

        Identifier identifier = new Identifier(PROJECT_MANAGER_TYPE, "", PROJECT_NAME, "");
        Project project = new Project(identifier, "", "", new TreeSet<>(), new TreeSet<>(),
                ProcessedDeclaredLicense.EMPTY, VcsInfo.EMPTY, VcsInfo.EMPTY, "", null,
                new TreeSet<>(Set.of(PROJECT_SCOPE)));
        Map<String, DependencyGraph> dependencyGraphs = generateDependencyGraphs(packages, project);
        AnalyzerResult analyzerResult = new AnalyzerResult(new TreeSet<>(Set.of(project)), packages, new TreeMap<>(), dependencyGraphs);
        AnalyzerRun analyzerRun = new AnalyzerRun(Instant.now(), Instant.now(), new Environment(), new AnalyzerConfiguration(), analyzerResult);
        OrtResult ortResult = new OrtResult(Repository.EMPTY, analyzerRun, null, null, null, new TreeMap<>());

        Path outputPath = Path.of(workspace.toString(), RESULT_FILE);
        Mapper.jsonMapper.writerWithDefaultPrettyPrinter().writeValue(outputPath.toFile(), ortResult);

        logger.info("successfully parse trace data");
    }

    private String getTaskId(Path workspace) throws IOException {
        try (Stream<Path> filePathStream = Files.walk(workspace)) {
            return filePathStream
                    .filter(Files::isRegularFile)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .filter(fileName -> fileName.endsWith("_sbom_tracer.sh"))
                    .findAny()
                    .map(fileName -> fileName.split("_")[0])
                    .orElseThrow(() -> new RuntimeException("Can't find *_sbom_tracer.sh"));
        }
    }

    private OrtResult ortAnalyze(Path workspace) {
        logger.info("start to run ort analyze");

        Analyzer analyzer = new Analyzer(new AnalyzerConfiguration(), Map.of());
        Analyzer.ManagedFileInfo info = analyzer.findManagedFiles(
                workspace.toFile(), PackageManager.Companion.getALL(), new RepositoryConfiguration());

        if (info.getManagedFiles().isEmpty()) {
            logger.error("No definition files found.");
            throw new RuntimeException("No definition files found.");
        }

        Map<String, List<File>> filesPerManager = info.getManagedFiles().entrySet().stream()
                .collect(Collectors.toMap(entry -> entry.getKey().getManagerName(), Map.Entry::getValue));
        AtomicInteger count = new AtomicInteger();
        filesPerManager.forEach((manager, files) -> {
            count.addAndGet(files.size());
            logger.info("Found {} {} definition file(s)", files.size(), manager);
        });
        logger.info("Found {} definition file(s) from {} package manager(s) in total.", count, filesPerManager.size());

        OrtResult ortResult = analyzer.analyze(info, PackageCurationProvider.EMPTY);
        if (Objects.isNull(ortResult.getAnalyzer())) {
            logger.error("There was an error creating the analyzer result.");
            throw new RuntimeException("There was an error creating the analyzer result.");
        }

        logger.info("successfully run ort analyze");
        return ortResult;
    }

    private SpdxDocument ortSpdxReport(OrtResult ortResult, String productName) {
        logger.info("start to run ort spdx report");

        SpdxDocumentModelMapper.SpdxDocumentParams params = new SpdxDocumentModelMapper.SpdxDocumentParams(productName, "", "");

        LicenseInfoResolver licenseInfoResolver = new LicenseInfoResolver(
                new DefaultLicenseInfoProvider(ortResult, new SimplePackageConfigurationProvider(List.of())),
                new CopyrightGarbage(), false, null, LicenseFilenamePatterns.Companion.getInstance());

        SpdxDocument spdxDocument = SpdxDocumentModelMapper.INSTANCE.map(ortResult, licenseInfoResolver, new DefaultLicenseTextProvider(), params);

        logger.info("successfully run ort spdx report");
        return spdxDocument;
    }

    private Map<String, DependencyGraph> generateDependencyGraphs(Set<CuratedPackage> packages, Project project) {
        List<Identifier> packageIds = packages.stream().map(p -> p.getPkg().getId()).toList();
        List<DependencyGraphNode> nodes = IntStream.range(0, packages.size())
                .mapToObj(i -> new DependencyGraphNode(i, 0, PackageLinkage.DYNAMIC, new ArrayList<>()))
                .collect(Collectors.toList());
        Map<String, List<RootDependencyIndex>> scopes = new HashMap<>();
        scopes.put(":%s::%s".formatted(project.getId().getName(), PROJECT_SCOPE),
                IntStream.range(0, packages.size())
                        .mapToObj(i -> new RootDependencyIndex(i, 0))
                        .collect(Collectors.toList()));
        DependencyGraph dependencyGraph = new DependencyGraph(packageIds, new TreeSet<>(), scopes, nodes, new ArrayList<>());
        Map<String, DependencyGraph> dependencyGraphs = new HashMap<>();
        dependencyGraphs.put(project.getId().getType(), dependencyGraph);
        return dependencyGraphs;
    }
}
