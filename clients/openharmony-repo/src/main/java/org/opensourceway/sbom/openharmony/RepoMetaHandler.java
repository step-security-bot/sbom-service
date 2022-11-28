package org.opensourceway.sbom.openharmony;

import org.opensourceway.sbom.openharmony.vo.RepoMetaVo;

import java.util.Set;

public interface RepoMetaHandler {
    Set<RepoMetaVo> fetchRepoMeta();
}
