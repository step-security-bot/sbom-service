package org.opensourceway.sbom.clients.vcs;

import reactor.core.publisher.Mono;

import java.nio.file.Path;

public interface VcsApi {
    Mono<?> getRepoInfo(String org, String repo);

    default Path downloadRepoArchive(Path downloadDir, String org, String repo, String branch) {
        throw new RuntimeException("not implemented");
    }
}
