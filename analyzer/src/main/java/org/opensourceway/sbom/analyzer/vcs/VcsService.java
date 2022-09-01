package org.opensourceway.sbom.analyzer.vcs;

import org.opensourceway.sbom.analyzer.model.RepoInfo;

public interface VcsService {
    RepoInfo getRepoInfo(String org, String repo);
}
