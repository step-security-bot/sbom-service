package org.opensourceway.sbom.manager.batch.processor.license;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.service.license.LicenseService;
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
import java.util.UUID;

public class ExtractLicensesProcessor implements ItemProcessor<List<ExternalPurlRef>, List<Pair<Package, License>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractLicensesProcessor.class);
    @Autowired
    @Qualifier("licenseServiceImpl")
    private LicenseService licenseService;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;

    @Nullable
    @Override
    public List<Pair<Package, License>> process(List<ExternalPurlRef> chunk) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseProcessor sbomId:{}, chunk size:{}, first item id:{}",
                sbomId,
                chunk.size(),
                CollectionUtils.isEmpty(chunk) ? "" : chunk.get(0).getId().toString());

        List<Pair<Package, License>> resultSet = licenseService.extractLicenseForPurlRefChunk(sbomId, chunk);

        logger.info("finish ExtractLicenseProcessor sbomId:{}, resultSet size:{}", sbomId, resultSet.size());
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