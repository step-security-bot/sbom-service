package org.opensourceway.sbom.manager.batch.writer.vul;

import org.apache.commons.lang3.tuple.Pair;
import org.openeuler.sbom.manager.model.ExternalPurlRef;
import org.openeuler.sbom.manager.service.vul.VulService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemWriter;

import java.util.List;
import java.util.Set;

public class ExternalPurlRefListWriter implements ItemWriter<Set<Pair<ExternalPurlRef, Object>>> {

    private static final Logger logger = LoggerFactory.getLogger(ExternalPurlRefListWriter.class);

    private final VulService vulService;


    public ExternalPurlRefListWriter(VulService vulService) {
        this.vulService = vulService;
    }

    public VulService getVulService() {
        return vulService;
    }

    @Override
    public void write(List<? extends Set<Pair<ExternalPurlRef, Object>>> chunks) {
        logger.info("start ExternalPurlRefListWriter service name:{}, chunk size:{}", getVulService().getClass().getName(), chunks.size());
        for (Set<Pair<ExternalPurlRef, Object>> externalVulRefSet : chunks) {
            getVulService().persistExternalVulRefChunk(externalVulRefSet);
        }
        logger.info("finish ExternalPurlRefListWriter");
    }

}
