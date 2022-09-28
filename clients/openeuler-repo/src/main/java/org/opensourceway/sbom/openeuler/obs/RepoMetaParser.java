package org.opensourceway.sbom.openeuler.obs;

import org.opensourceway.sbom.openeuler.obs.vo.RepoInfoVo;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

public interface RepoMetaParser {

    Set<RepoInfoVo> fetchObsMetaSourceCode() throws IOException;

    Set<RepoInfoVo> parseRepoInfoFromZip(Path sourceZipPath) throws IOException;

    void fetchRepoBuildFileInfo(Set<RepoInfoVo> repoInfoSet);

    void fetchRepoPackageAndPatchInfo(Set<RepoInfoVo> repoInfoSet);

    void fetchRepoUpstreamInfo(Set<RepoInfoVo> repoInfoSet);

}
