package org.opensourceway.sbom.api.repo;

import org.opensourceway.sbom.model.pojo.vo.repo.RepoMetaVo;

import java.util.Set;

public interface RepoMetaHandler {
    Set<RepoMetaVo> fetchRepoMeta();
}
