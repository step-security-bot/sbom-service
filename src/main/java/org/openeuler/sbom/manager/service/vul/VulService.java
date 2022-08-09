package org.openeuler.sbom.manager.service.vul;

import org.openeuler.sbom.manager.model.Sbom;
import org.springframework.scheduling.annotation.Async;

public interface VulService {

    @Async
    void persistExternalVulRefForSbom(Sbom sbom, Boolean blocking);
}
