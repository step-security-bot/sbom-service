package org.openeuler.sbom.analyzer.vcs;

import org.openeuler.sbom.analyzer.model.RepoInfo;

public interface VcsService {
    RepoInfo getRepoInfo(String org, String repo);
}
