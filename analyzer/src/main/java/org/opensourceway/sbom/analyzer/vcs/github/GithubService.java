package org.opensourceway.sbom.analyzer.vcs.github;

import org.opensourceway.sbom.analyzer.model.RepoInfo;
import org.opensourceway.sbom.analyzer.vcs.VcsService;
import org.opensourceway.sbom.clients.vcs.VcsEnum;
import org.opensourceway.sbom.clients.vcs.github.GithubApi;
import org.opensourceway.sbom.clients.vcs.github.model.GithubRepoInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

@Component("github.com")
public class GithubService implements VcsService {

    private static final Logger logger = LoggerFactory.getLogger(GithubService.class);

    @Autowired
    private GithubApi githubApi;

    @Override
    public RepoInfo getRepoInfo(String org, String repo) {
        GithubRepoInfo.RepoInfo repoInfo = new GithubRepoInfo.RepoInfo();
        try {
            repoInfo = Optional.ofNullable(githubApi.getRepoInfo(org, repo).block())
                    .orElse(new GithubRepoInfo.RepoInfo());
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
