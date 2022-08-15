package org.openeuler.sbom.manager.service.vul;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public abstract class AbstractVulService implements VulService {

    private static final Logger logger = LoggerFactory.getLogger(AbstractVulService.class);

    protected void reportVulFetchFailure(UUID sbomId) {
        logger.info("report vulnerability fetch failure for sbom {}", sbomId);
    }
}
