package org.opensourceway.sbom.manager.batch.writer.license;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.service.license.LicenseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExternalPurlRefListWriter implements ItemWriter<Set<Pair<ExternalPurlRef, Object>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExternalPurlRefListWriter.class);

    private final LicenseService licenseService;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;


    public ExternalPurlRefListWriter(LicenseService licenseService) {
        this.licenseService = licenseService;
    }

    public LicenseService getLicenseService() {
        return licenseService;
    }

    @Override
    public void write(List<? extends Set<Pair<ExternalPurlRef, Object>>> chunks) {
        logger.info("start ExternalPurlRefListWriter service name:{}, chunk size:{}", getLicenseService().getClass().getName(), chunks.size());
        for (Set<Pair<ExternalPurlRef, Object>> externalVulRefSet : chunks) {
            getLicenseService().persistExternalLicenseRefChunk(externalVulRefSet,
                    (Map<String, Map<String, String>>) this.stepExecution.getExecutionContext().get("licenseInfoMap"));
        }
        logger.info("finish ExternalPurlRefListWriter");
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        return null;
    }
}
