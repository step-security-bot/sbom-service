package org.opensourceway.sbom.analyzer.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.model.pojo.vo.analyzer.ProcessData;
import org.opensourceway.sbom.model.pojo.vo.analyzer.ProcessIdentifier;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@Component
public class ProcessParser {
    private static final Logger logger = LoggerFactory.getLogger(ProcessParser.class);

    private static final String EXECSNOOP_LOG = "execsnoop.log";

    private static final String SBOM_TRACER_SHELL_SUFFIX = "_sbom_tracer.sh";

    public List<ProcessIdentifier> getAllProcess(Path workspace) throws IOException {
        logger.info("start to get all processes");
        List<ProcessIdentifier> allProcess = new ArrayList<>();
        String sbomTracerShell = getSbomTracerShell(workspace);
        var wrapper = new Object() {int mainPid = -1;};
        try(Stream<String> stream = Files.lines(Paths.get(workspace.toString(), EXECSNOOP_LOG))) {
            stream.forEach(line -> {
                ProcessData data;
                try {
                    data = Mapper.jsonMapper.readValue(line.trim(), ProcessData.class);
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
                if (StringUtils.contains(data.fullCmd(), sbomTracerShell)) {
                    wrapper.mainPid = data.pid();
                }
                if (StringUtils.contains(data.fullCmd(), sbomTracerShell) ||
                        data.ancestorPids().contains(wrapper.mainPid)) {
                    allProcess.add(new ProcessIdentifier(data.pid(), data.ppid(), data.cmd()));
                }
            });
        } catch (IOException e) {
            logger.error("failed to get all processes", e);
            throw new RuntimeException(e);
        }
        logger.info("successfully got all processes");
        return allProcess;
    }

    private String getSbomTracerShell(Path workspace) throws IOException {
        try (Stream<Path> filePathStream = Files.walk(workspace)) {
            return filePathStream
                    .filter(Files::isRegularFile)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .filter(fileName -> fileName.endsWith(SBOM_TRACER_SHELL_SUFFIX))
                    .findAny()
                    .orElseThrow(() -> new RuntimeException("Can't find *_sbom_tracer.sh"));
        }
    }
}
