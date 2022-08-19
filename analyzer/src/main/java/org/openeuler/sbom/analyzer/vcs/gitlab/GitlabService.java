package org.openeuler.sbom.analyzer.vcs.gitlab;

import org.openeuler.sbom.analyzer.model.RepoInfo;
import org.openeuler.sbom.analyzer.vcs.VcsService;
import org.openeuler.sbom.clients.vcs.VcsEnum;
import org.openeuler.sbom.clients.vcs.gitlab.GitlabApi;
import org.openeuler.sbom.clients.vcs.gitlab.model.GitlabRepoInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

@Component("gitlab.com")
public class GitlabService implements VcsService {

    private static final Logger logger = LoggerFactory.getLogger(GitlabService.class);

    @Autowired
    private GitlabApi gitlabApi;

    @Override
    public RepoInfo getRepoInfo(String org, String repo) {
        GitlabRepoInfo.RepoInfo repoInfo = new GitlabRepoInfo.RepoInfo();
        try {
            repoInfo = Optional.ofNullable(gitlabApi.getRepoInfo(org, repo).block())
                    .orElse(new GitlabRepoInfo.RepoInfo());
        } catch (Exception e) {
            logger.warn("failed to get repo info from {} for [org: '{}', repo: '{}']", VcsEnum.GITLAB, org, repo, e);
        }

        SortedSet<String> authors = new TreeSet<>(Set.of(Optional.ofNullable(repoInfo.owner())
                .orElse(new GitlabRepoInfo.Owner("")).name()));
        SortedSet<String> licenses = new TreeSet<>(Set.of(Optional.ofNullable(repoInfo.license())
                .orElse(new GitlabRepoInfo.License("")).name()));
        return new RepoInfo(authors, licenses,
                Optional.ofNullable(repoInfo.description()).orElse(""),
                Optional.ofNullable(repoInfo.homepage()).orElse(""),
                Optional.ofNullable(repoInfo.repoUrl()).orElse(""));
    }
}
