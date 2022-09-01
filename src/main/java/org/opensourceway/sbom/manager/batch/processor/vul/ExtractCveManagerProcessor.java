package org.opensourceway.sbom.manager.batch.processor.vul;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.openeuler.sbom.manager.model.ExternalPurlRef;
import org.openeuler.sbom.manager.service.vul.VulService;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public class ExtractCveManagerProcessor implements ItemProcessor<List<ExternalPurlRef>, Set<Pair<ExternalPurlRef, Object>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractCveManagerProcessor.class);

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Autowired
    @Qualifier("cveManagerServiceImpl")
    VulService cveManagerService;

    @Nullable
    @Override
    public Set<Pair<ExternalPurlRef, Object>> process(List<ExternalPurlRef> chunk) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractCveManagerProcessor sbomId:{}, chunk size:{}", sbomId, chunk.size());

        Set<Pair<ExternalPurlRef, Object>> resultSet = cveManagerService.extractVulForPurlRefChunk(sbomId, chunk);

        logger.info("finish ExtractCveManagerProcessor resultSet size:{}", resultSet.size());
        return resultSet;
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