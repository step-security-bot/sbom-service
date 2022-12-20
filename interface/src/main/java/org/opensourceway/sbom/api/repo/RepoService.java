package org.opensourceway.sbom.api.repo;

import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.response.sbom.UpstreamAndPatchInfoResponse;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;

import java.io.IOException;
import java.util.List;
import java.util.Set;

public interface RepoService {

    Set<RepoInfoVo> fetchOpenEulerRepoMeta() throws IOException;

    UpstreamAndPatchInfoResponse queryUpstreamAndPatchInfo(String packageId);

    List<RepoMeta> fetchOpenHarmonyRepoMeta();
}
