package org.opensourceway.sbom.service.vul;

import org.opensourceway.sbom.api.vul.VulService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public abstract class AbstractVulService implements VulService {

    private static final Logger logger = LoggerFactory.getLogger(AbstractVulService.class);

    protected void reportVulFetchFailure(UUID sbomId) {
        logger.info("report vulnerability fetch failure for sbom {}", sbomId);
    }
}
