package org.opensourceway.sbom.analyzer.parser.handler.handlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.model.GitSubmoduleData;
import org.opensourceway.sbom.analyzer.parser.handler.Handler;
import org.opensourceway.sbom.analyzer.parser.handler.HandlerEnum;
import org.opensourceway.sbom.analyzer.utils.PackageGenerator;
import org.opensourceway.sbom.utils.Mapper;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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
        if (Pattern.compile("[\\da-z]*").matcher(versionString).matches()) {
            logger.warn("get a commit id instead of a tag");
        }
        if (versionString.contains("/")) {
            logger.warn("get a branch id instead of a tag");
        }

        String commitId = data.commitId().trim();
        Matcher m = Pattern.compile("\\((\\D*([.+\\-\\da-z]*))-.*-.*\\)").matcher(versionString);
        if (m.matches() && StringUtils.isNotEmpty(m.group(2))) {
            String tag = m.group(1);
            String version = m.group(2);
            return packageGenerator.generatePackageFromVcs(host, org, repo, version, commitId, tag, null);
        }

        if (StringUtils.isEmpty(commitId)) {
            logger.warn("empty commit id");
            return null;
        }
        return packageGenerator.generatePackageFromVcs(host, org, repo, commitId, commitId, null, null);
    }
}
