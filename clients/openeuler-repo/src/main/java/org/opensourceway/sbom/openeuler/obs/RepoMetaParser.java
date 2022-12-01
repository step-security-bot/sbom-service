package org.opensourceway.sbom.openeuler.obs;

import org.opensourceway.sbom.openeuler.obs.vo.RepoInfoVo;
import org.springframework.data.util.Pair;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

public interface RepoMetaParser {

    Set<RepoInfoVo> fetchObsMetaSourceCode() throws IOException;

    Set<RepoInfoVo> parseRepoInfoFromZip(Path sourceZipPath) throws IOException;

    Pair<Boolean, String> isRepoChanged(RepoInfoVo repoInfo, String lastCommitId);

    void fetchRepoBuildFileInfo(RepoInfoVo repoInfo);

    void fetchRepoPackageAndPatchInfo(RepoInfoVo repoInfo);

}
