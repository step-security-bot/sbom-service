package org.opensourceway.sbom.analyzer.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.opensourceway.sbom.analyzer.pkggen.PackageGenerator;
import org.opensourceway.sbom.model.enums.VcsEnum;
import org.opensourceway.sbom.model.pojo.vo.analyzer.HttpSniffData;
import org.opensourceway.sbom.model.pojo.vo.analyzer.ProcessIdentifier;
import org.opensourceway.sbom.utils.Mapper;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
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
    private Map<String, PackageGenerator> packageGenerators;

    private static final String HTTP_SNIFF_LOG = "sslsniff.log";

    @PostConstruct
    private void appendPackageGenerators() {
        PackageGenerator vcsPackageGenerator = packageGenerators.get("vcs");
        Arrays.stream(VcsEnum.values()).forEach(vcsEnum -> packageGenerators.put(vcsEnum.getVcsHost(), vcsPackageGenerator));
    }

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
        for (String suffix : Arrays.asList(".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tar", ".tgz", ".gz", ".xz", ".tbz2")) {
            path = path.replace(suffix, "");
        }

        if (Objects.isNull(packageGenerators.get(host))) {
            return null;
        }
        return packageGenerators.get(host).generatePackage(host, path, url);
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
