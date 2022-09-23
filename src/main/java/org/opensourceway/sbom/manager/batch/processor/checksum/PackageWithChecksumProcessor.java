package org.opensourceway.sbom.manager.batch.processor.checksum;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.service.checksum.ChecksumService;
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

public class PackageWithChecksumProcessor implements ItemProcessor<Package, List<List<ExternalPurlRef>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(PackageWithChecksumProcessor.class);
    @Autowired
    @Qualifier("checksumServiceImpl")
    private ChecksumService checksumService;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;

    @Nullable
    @Override
    public List<List<ExternalPurlRef>> process(Package pkg) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start PackageWithChecksumProcessor sbomId:{}", sbomId);

        List<List<ExternalPurlRef>> resultList = checksumService.extractGAVByChecksumRef(pkg.getId(),
                ReferenceCategory.EXTERNAL_MANAGER.name(), SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);

        logger.info("finish PackageWithChecksumProcessor resultSet size:{}", resultList.size());
        return resultList;
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
