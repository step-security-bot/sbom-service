package org.opensourceway.sbom.utils;


import org.opensourceway.sbom.model.pojo.vo.repo.OpenEulerAdvisorVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class OpenEulerAdvisorParser {
    private static final Logger logger = LoggerFactory.getLogger(OpenEulerAdvisorParser.class);

    private static final String LOCATION_DELIMITER = "/";

    @Value("${github.domain.url}")
    private String githubDomainUrl;

    @Value("${gitlab.domain.url}")
    private String gitlabDomainUrl;

    @Value("${gitee.domain.url}")
    private String giteeDomainUrl;

    @Value("${gnu-ftp.domain.url}")
    private String gnuFtpDomainUrl;

    @Value("${gitlab-gnome.domain.url}")
    private String gitlabGnomeDomainUrl;

    public String parseUpstreamLocation(String advisorContent) {
        return parseUpstreamLocation(advisorContent, null);
    }

    public String parseUpstreamLocation(String advisorContent, String upstreamDownloadUrl) {
        OpenEulerAdvisorVo advisor = YamlUtil.parseFromStr(advisorContent);
        if (advisor == null || !StringUtils.hasText(advisor.getVersionControl()) || "NA".equals(advisor.getVersionControl())) {
            return null;
        }

        String location;
        switch (advisor.getVersionControl().toLowerCase()) {
            case "github" -> location = parseCommonAdvisor(advisor, githubDomainUrl);
            case "gitlab" -> location = parseCommonAdvisor(advisor, gitlabDomainUrl);
            case "gitee" -> location = parseCommonAdvisor(advisor, giteeDomainUrl);
            case "gnu-ftp" -> location = parseCommonAdvisor(advisor, gnuFtpDomainUrl);
            case "gitlab.gnome" -> location = parseCommonAdvisor(advisor, gitlabGnomeDomainUrl);
            case "git", "svn", "cvs", "central", "ftp", "sourceforge", "fossil", "hg", "hg-raw", "http://emma.sourceforge.net/", "npm", "registry" ->
                    location = parseDownloadAdvisor(advisor);
            case "github.gnome" -> location = parseGithubGnomeAdvisor(advisor, githubDomainUrl);
            case "pypi", "metacpan" -> location = upstreamDownloadUrl;
            default -> throw new RuntimeException("OpenEulerAdvisorParser not support vcs control:%s, advisorContent:%s, upstreamDownloadUrl:%s"
                    .formatted(advisor.getVersionControl(), advisorContent, upstreamDownloadUrl));
        }

        if (location == null) {
            throw new RuntimeException("OpenEulerAdvisorParser not support, advisorContent:%s, upstreamDownloadUrl:%s"
                    .formatted(advisorContent, upstreamDownloadUrl));
        }
        return location;
    }

    private String parseCommonAdvisor(OpenEulerAdvisorVo advisor, String vcsDomainUrl) {
        if (StringUtils.hasText(advisor.getUrl())) {
            return advisor.getUrl();
        } else if (StringUtils.hasText(advisor.getGitUrl())) {
            return advisor.getGitUrl();
        } else if (StringUtils.hasText(advisor.getSrcRepo())) {
            return String.join(LOCATION_DELIMITER, vcsDomainUrl, advisor.getSrcRepo());
        }
        return null;
    }

    private String parseDownloadAdvisor(OpenEulerAdvisorVo advisor) {
        if (StringUtils.hasText(advisor.getUrl())) {
            return advisor.getUrl();
        } else if (StringUtils.hasText(advisor.getGitUrl())) {
            return advisor.getGitUrl();
        } else if (StringUtils.hasText(advisor.getSrcRepo())) {
            return advisor.getSrcRepo();
        }
        return null;
    }

    private String parseGithubGnomeAdvisor(OpenEulerAdvisorVo advisor, String vcsDomainUrl) {
        if (StringUtils.hasText(advisor.getUrl())) {
            return advisor.getUrl();
        } else if (StringUtils.hasText(advisor.getGitUrl())) {
            return advisor.getGitUrl();
        } else if (StringUtils.hasText(advisor.getSrcRepo())) {
            return String.join(LOCATION_DELIMITER, vcsDomainUrl, "GNOME", advisor.getSrcRepo());
        }
        return null;
    }

}
