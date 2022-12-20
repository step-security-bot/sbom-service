package org.opensourceway.sbom.api.vul;

import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface VulService {

    Integer getBulkRequestSize();

    boolean needRequest();

    Set<Pair<ExternalPurlRef, Object>> extractVulForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk,
                                                                 String productType);

    void persistExternalVulRefChunk(Set<Pair<ExternalPurlRef, Object>> externalVulRefSet);
}
