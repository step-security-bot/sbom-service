package org.opensourceway.sbom.analyzer.vcs.github;

import org.opensourceway.sbom.analyzer.vcs.VcsService;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.enums.VcsEnum;
import org.opensourceway.sbom.model.pojo.response.vcs.github.GithubRepoInfo;
import org.opensourceway.sbom.model.pojo.vo.vcs.RepoInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

@Component("github.com")
public class GithubService implements VcsService {

    private static final Logger logger = LoggerFactory.getLogger(GithubService.class);

    @Autowired
    @Qualifier("githubApi")
    private VcsApi githubApi;

    @Override
    public RepoInfo getRepoInfo(String org, String repo) {
        GithubRepoInfo.RepoInfo repoInfo = new GithubRepoInfo.RepoInfo();
        try {
            Object result = githubApi.getRepoInfo(org, repo).block();
            if (Objects.nonNull(result)) {
                repoInfo = (GithubRepoInfo.RepoInfo) result;
            }
        } catch (Exception e) {
            logger.warn("failed to get repo info from {} for [org: '{}', repo: '{}']", VcsEnum.GITHUB, org, repo, e);
        }

        SortedSet<String> authors = new TreeSet<>(Set.of(Optional.ofNullable(repoInfo.owner())
                .orElse(new GithubRepoInfo.Owner("")).login()));
        SortedSet<String> licenses = new TreeSet<>(Set.of(Optional.ofNullable(repoInfo.license())
                .orElse(new GithubRepoInfo.License("")).name()));
        return new RepoInfo(authors, licenses,
                Optional.ofNullable(repoInfo.description()).orElse(""),
                Optional.ofNullable(repoInfo.homepage()).orElse(""),
                Optional.ofNullable(repoInfo.repoUrl()).orElse(""));
    }

    @Override
    public String getTagDownloadUrl(String org, String repo, String tag) {
        return MessageFormat.format("https://{0}/{1}/{2}/archive/refs/tags/{3}.tar.gz",
                VcsEnum.GITHUB.getVcsHost(), org, repo, tag);
    }

    @Override
    public String getCommitUrl(String org, String repo, String commitId) {
        return MessageFormat.format("https://{0}/{1}/{2}/commit/{3}",
                VcsEnum.GITHUB.getVcsHost(), org, repo, commitId);
    }
}
