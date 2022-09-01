package org.opensourceway.sbom.manager.service.vul;

import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.Sbom;
import org.springframework.scheduling.annotation.Async;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface VulService {

    @Async
    void persistExternalVulRefForSbom(Sbom sbom, Boolean blocking);

    Integer getBulkRequestSize();

    boolean needRequest();

    Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk);

    void persistExternalVulRefChunk(Set<Pair<ExternalPurlRef, Object>> externalVulRefSet);
}
