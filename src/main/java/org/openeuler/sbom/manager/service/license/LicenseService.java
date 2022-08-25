package org.openeuler.sbom.manager.service.license;

import org.openeuler.sbom.manager.model.Sbom;
import org.springframework.scheduling.annotation.Async;

public interface LicenseService {

    @Async
    void persistLicenseForSbom(Sbom sbom, Boolean blocking);
}
