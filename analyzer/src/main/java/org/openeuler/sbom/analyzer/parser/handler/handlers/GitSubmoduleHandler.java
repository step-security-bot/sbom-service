package org.openeuler.sbom.analyzer.parser.handler.handlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.StringUtils;
import org.openeuler.sbom.analyzer.model.GitSubmoduleData;
import org.openeuler.sbom.analyzer.parser.handler.Handler;
import org.openeuler.sbom.analyzer.parser.handler.HandlerEnum;
import org.openeuler.sbom.analyzer.utils.PackageGenerator;
import org.openeuler.sbom.utils.Mapper;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component("git_submodule")
public class GitSubmoduleHandler implements Handler {

    private static final Logger logger = LoggerFactory.getLogger(GitSubmoduleHandler.class);

    @Autowired
    private PackageGenerator packageGenerator;

    private final HandlerEnum handlerType = HandlerEnum.GIT_SUBMODULE;

    @Override
    public CuratedPackage handle(String recordJson) {
        GitSubmoduleData data;
        try {
            data = Mapper.jsonMapper.readValue(recordJson, GitSubmoduleData.class);
        } catch (JsonProcessingException e) {
            return null;
        }

        if (!StringUtils.equals(data.tag(), handlerType.getTag())) {
            logger.warn("invalid tag for record '{}'", recordJson);
            return null;
        }

        logger.info("handling git submodule record: '{}'", recordJson);

        Matcher matcher = Pattern.compile("https://(.*?)/(.*?)/(.*?)\\.git").matcher(data.url().trim());
        if (!matcher.matches()) {
            logger.warn("invalid git url for record '{}'", recordJson);
            return null;
        }
        String host = matcher.group(1);
        String org = matcher.group(2);
        String repo = matcher.group(3);

        String versionString = data.versionString().trim();
        String[] versionStringSplit = versionString.split("/");
        if (versionStringSplit.length > 1) {
            versionString = versionStringSplit[versionStringSplit.length - 1];
        }

        List<String> patterns = Arrays.asList(
                "\\D*([.+\\-\\da-z]*)-.*-.*",
                "\\D*([.+\\-\\da-z]*)-.*",
                "\\D*([.+\\-\\da-z]*)\\)"
        );
        for (String pattern : patterns) {
            Matcher m = Pattern.compile(pattern).matcher(versionString);
            if (m.matches()) {
                String version = m.group(1);
                return packageGenerator.generatePackageFromVcs(host, org, repo, version, data.commitId().trim(), "");
            }
        }

        logger.warn("invalid record '{}'", recordJson);
        return null;
    }
}
