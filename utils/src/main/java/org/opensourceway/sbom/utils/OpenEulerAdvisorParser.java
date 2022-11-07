package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.pojo.OpenEulerAdvisorVo;
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
        OpenEulerAdvisorVo advisor = YamlUtil.parseFromStr(advisorContent);
        if (advisor == null || !StringUtils.hasText(advisor.getVersionControl()) || "NA".equals(advisor.getVersionControl())) {
            return null;
        }

        String location = null;
        switch (advisor.getVersionControl().toLowerCase()) {
            case "github" -> location = parseCommonAdvisor(advisor, githubDomainUrl);
            case "gitlab" -> location = parseCommonAdvisor(advisor, gitlabDomainUrl);
            case "gitee" -> location = parseCommonAdvisor(advisor, giteeDomainUrl);
            case "gnu-ftp" -> location = parseCommonAdvisor(advisor, gnuFtpDomainUrl);
            case "gitlab.gnome" -> location = parseCommonAdvisor(advisor, gitlabGnomeDomainUrl);
            case "git", "svn", "sourceforge" -> location = parseDownloadAdvisor(advisor);
            default ->
                    logger.error("OpenEulerAdvisorParser not support vcs control:{}, advisorContent:{}", advisor.getVersionControl(), advisorContent);
        }

        if (location == null) {
            logger.error("OpenEulerAdvisorParser not support, advisorContent:{}", advisorContent);
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

}
