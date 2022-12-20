package org.opensourceway.sbom.api.vcs;

import reactor.core.publisher.Mono;

import java.nio.file.Path;
import java.util.List;

public interface VcsApi {

    default String getDefaultBaseUrl() {
        throw new RuntimeException("not implemented");
    }

    Mono<?> getRepoInfo(String org, String repo);

    default Path downloadRepoArchive(Path downloadDir, String org, String repo, String branch) {
        throw new RuntimeException("not implemented");
    }

    default List<?> findRepoFiles(String org, String repo, String branch, String fileDir, String fileNameRegex) {
        throw new RuntimeException("not implemented");
    }

    default String getFileContext(String downloadUrl) {
        throw new RuntimeException("not implemented");
    }

    default List<String> getOrgRepoNames(String org, Integer page, Integer perPage) {
        throw new RuntimeException("not implemented");
    }

    default List<String> getRepoTags(String org, String repo) {
        throw new RuntimeException("not implemented");
    }

    default List<?> getRepoBranches(String org, String repo) {
        throw new RuntimeException("not implemented");
    }
}
