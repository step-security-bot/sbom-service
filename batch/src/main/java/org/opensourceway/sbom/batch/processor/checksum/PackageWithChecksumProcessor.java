package org.opensourceway.sbom.batch.processor.checksum;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.checksum.ChecksumService;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
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
        logger.info("start PackageWithChecksumProcessor sbomId:{}, pkg id:{}", sbomId, pkg.getId().toString());

        List<List<ExternalPurlRef>> resultList = checksumService.extractGAVByChecksumRef(pkg.getId(),
                ReferenceCategory.EXTERNAL_MANAGER.name(), SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);

        logger.info("finish PackageWithChecksumProcessor sbomId:{}, resultSet size:{}", sbomId, resultList.size());
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
