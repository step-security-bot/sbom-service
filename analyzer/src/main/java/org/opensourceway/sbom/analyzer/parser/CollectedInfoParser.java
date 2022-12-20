package org.opensourceway.sbom.analyzer.parser;

import org.opensourceway.sbom.analyzer.parser.handler.Handler;
import org.opensourceway.sbom.model.pojo.vo.analyzer.ProcessIdentifier;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

@Component
public class CollectedInfoParser implements Parser {
    private static final Logger logger = LoggerFactory.getLogger(CollectedInfoParser.class);

    @Autowired
    private List<Handler> handlers;

    private static final String COLLECTED_INFO_LOG = "locally_collected_info.log";

    @Override
    public Set<CuratedPackage> parse(Path workspace, List<ProcessIdentifier> allProcess) {
        logger.info("start to parse collected info");
        Set<CuratedPackage> packages = new TreeSet<>();
        try(Stream<String> stream = Files.lines(Paths.get(workspace.toString(), COLLECTED_INFO_LOG))) {
            stream.distinct().forEach(line -> handlers.stream()
                    .map(handler -> handler.handle(line.trim()))
                    .filter(Objects::nonNull)
                    .forEach(packages::add));
        } catch (IOException e) {
            logger.error("failed to parse collected info", e);
            throw new RuntimeException(e);
        }
        logger.info("successfully parsed collected info");
        return packages;
    }
}
