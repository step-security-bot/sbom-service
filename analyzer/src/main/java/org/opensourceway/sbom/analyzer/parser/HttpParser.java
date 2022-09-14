package org.opensourceway.sbom.analyzer.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.model.HttpSniffData;
import org.opensourceway.sbom.analyzer.model.ProcessIdentifier;
import org.opensourceway.sbom.analyzer.utils.PackageGenerator;
import org.opensourceway.sbom.utils.Mapper;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class HttpParser implements Parser {

    private static final Logger logger = LoggerFactory.getLogger(HttpParser.class);

    @Autowired
    private PackageGenerator packageGenerator;

    private static final String HTTP_SNIFF_LOG = "sslsniff.log";

    @Override
    public Set<CuratedPackage> parse(Path workspace, List<ProcessIdentifier> allProcess) {
        logger.info("start to parse HTTP");
        Set<CuratedPackage> packages;
        try(Stream<String> stream = Files.lines(Paths.get(workspace.toString(), HTTP_SNIFF_LOG))) {
            packages = stream.map(line -> {
                        try {
                            return Mapper.jsonMapper.readValue(line.trim(), HttpSniffData.class);
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .filter(data -> allProcess.contains(new ProcessIdentifier(data.pid(), data.ppid(), data.cmd())))
                    .map(data -> getHostPath(data.data()))
                    .map(this::getPackage)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toCollection(TreeSet::new));
        } catch (IOException e) {
            logger.error("failed to parse HTTP", e);
            throw new RuntimeException(e);
        }
        logger.info("successfully parsed HTTP");
        return packages;
    }

    protected CuratedPackage getPackage(HostPathWrapper wrapper) {
        String host = wrapper.host();
        String path = wrapper.path();
        path = resolveCache(path);
        String url = "https://" + host + path;
        for (String suffix : Arrays.asList(".tar.gz", ".tgz", ".tar.xz", ".zip", ".tar", ".gz", ".xz", ".tar.bz2", ".tbz2")) {
            path = path.replace(suffix, "");
        }

        String dirPattern = "/(.*?)/(.*?)/.*/(\\D*([.\\-_\\da-zA-Z]*))/.*";
        String packagePattern = "/(.*?)/(.*?)/.*/(\\D*([.\\-_\\da-zA-Z]*))";
        for (String pattern : Arrays.asList(dirPattern, packagePattern)) {
            Matcher matcher = Pattern.compile(pattern).matcher(path);
            if (matcher.matches()) {
                String org = matcher.group(1);
                String repo = matcher.group(2);
                String tag = matcher.group(3);
                String version = matcher.group(4);
                if (Pattern.compile("[a-zA-Z]*").matcher(tag).matches()) {
                    continue;
                }
                if (Stream.of(org, repo, tag, version).allMatch(StringUtils::isNotEmpty)) {
                    return packageGenerator.generatePackageFromVcs(host, org, repo, version, "", tag, url);
                }
            }
        }

        return null;
    }

    private HostPathWrapper getHostPath(String data) {
        String host = "";
        String path = "";
        for (String s : data.trim().split("\r\n")) {
            if (s.startsWith("Host")) {
                host = s.split(" ")[1];
            } else if (Stream.of("GET", "POST", "PUT", "HEAD").anyMatch(s::startsWith)) {
                path = s.split(" ")[1];
            }
        }
        return new HostPathWrapper(host, path);
    }

    private String resolveCache(String path) {
        Matcher matcher = Pattern.compile("(.*)/blazearchive/(.*)\\?.*").matcher(path);
        if (!matcher.matches()) {
            return path;
        }
        return "%s/archive/%s".formatted(matcher.group(1), matcher.group(2));
    }

    protected record HostPathWrapper(String host, String path) {}
}
