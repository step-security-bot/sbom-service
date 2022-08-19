package org.openeuler.sbom.analyzer.vcs.gitee;

import org.openeuler.sbom.analyzer.model.RepoInfo;
import org.openeuler.sbom.analyzer.vcs.VcsService;
import org.openeuler.sbom.clients.vcs.VcsEnum;
import org.openeuler.sbom.clients.vcs.gitee.GiteeApi;
import org.openeuler.sbom.clients.vcs.gitee.model.GiteeRepoInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

@Component("gitee.com")
public class GiteeService implements VcsService {

    private static final Logger logger = LoggerFactory.getLogger(GiteeService.class);

    @Autowired
    private GiteeApi giteeApi;

    @Override
    public RepoInfo getRepoInfo(String org, String repo) {
        GiteeRepoInfo.RepoInfo repoInfo = new GiteeRepoInfo.RepoInfo();
        try {
            repoInfo = Optional.ofNullable(giteeApi.getRepoInfo(org, repo).block())
                    .orElse(new GiteeRepoInfo.RepoInfo());
        } catch (Exception e) {
            logger.warn("failed to get repo info from {} for [org: '{}', repo: '{}']", VcsEnum.GITEE, org, repo, e);
        }

        SortedSet<String> authors = new TreeSet<>(Set.of(Optional.ofNullable(repoInfo.owner())
                .orElse(new GiteeRepoInfo.Owner("")).login()));
        SortedSet<String> licenses = new TreeSet<>(Set.of(Optional.ofNullable(repoInfo.license()).orElse("")));
        return new RepoInfo(authors, licenses,
                Optional.ofNullable(repoInfo.description()).orElse(""),
                Optional.ofNullable(repoInfo.homepage()).orElse(""),
                Optional.ofNullable(repoInfo.repoUrl()).orElse(""));
    }
}
