package org.opensourceway.sbom.manager.service.checksum;

import org.opensourceway.sbom.manager.model.ExternalPurlRef;

import java.util.List;
import java.util.UUID;

public interface ChecksumService {

    boolean needRequest();

    List<List<ExternalPurlRef>> extractGAVByChecksumRef(UUID pkgId, String category, String type);

    void persistExternalGAVRef(List<List<ExternalPurlRef>> externalPurlRefList);
}
