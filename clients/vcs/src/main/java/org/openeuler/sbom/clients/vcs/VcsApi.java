package org.openeuler.sbom.clients.vcs;

import reactor.core.publisher.Mono;

public interface VcsApi {
    Mono<?> getRepoInfo(String org, String repo);
}
