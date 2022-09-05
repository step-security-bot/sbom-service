package org.opensourceway.sbom.manager.service.license;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public abstract class AbstractLicenseService implements LicenseService {
    private static final Logger logger = LoggerFactory.getLogger(AbstractLicenseService.class);

    protected void reportLicenseFetchFailure(UUID sbomId) {
        logger.info("report License failure for sbom {}", sbomId);
    }
}
