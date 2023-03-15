package org.opensourceway.sbom.analyzer.parser.handler.handlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.parser.handler.HandlerEnum;
import org.opensourceway.sbom.analyzer.pkggen.VcsPackageGenerator;
import org.opensourceway.sbom.model.pojo.vo.analyzer.GitData;
import org.opensourceway.sbom.utils.Mapper;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class BaseGitHandler {
    private static final Logger logger = LoggerFactory.getLogger(BaseGitHandler.class);

    @Autowired
    private VcsPackageGenerator vcsPackageGenerator;

    protected CuratedPackage handle(String recordJson, HandlerEnum handlerType) {
        GitData data;
        try {
            data = Mapper.jsonMapper.readValue(recordJson, GitData.class);
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
        String commitId = data.commitId().trim();
        if (Pattern.compile("[\\da-z]*").matcher(versionString).matches()) {
            logger.warn("get a commit id instead of a tag");
            return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, commitId, commitId, null, null);
        }
        if (versionString.contains("/")) {
            logger.warn("get a branch id instead of a tag");
            return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, commitId, commitId, null, null);
        }

        // match pattern like 'v1.0.0-3036-g78f9368', 'v3.1.0' or 'curl-7_78_0'
        for (String pattern : List.of(
                "\\(?(\\D*([.+_\\-\\da-z]*))-.*-.*\\)?",
                "\\(?(\\D*([.+_\\-\\da-z]*))\\)?")) {
            Matcher m = Pattern.compile(pattern).matcher(versionString);
            if (m.matches() && StringUtils.isNotEmpty(m.group(2))) {
                String tag = m.group(1);
                String version = m.group(2);
                return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, tag, commitId, tag, null);
            }
        }
        return null;
    }
}
