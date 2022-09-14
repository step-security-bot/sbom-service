package org.opensourceway.sbom.analyzer.vcs;

import org.opensourceway.sbom.analyzer.model.RepoInfo;

public interface VcsService {
    RepoInfo getRepoInfo(String org, String repo);

    String getTagDownloadUrl(String org, String repo, String tag);

    String getCommitUrl(String org, String repo, String commitId);
}
