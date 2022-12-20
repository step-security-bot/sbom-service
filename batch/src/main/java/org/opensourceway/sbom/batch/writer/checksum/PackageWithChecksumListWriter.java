package org.opensourceway.sbom.batch.writer.checksum;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.checksum.ChecksumService;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;

import java.util.List;
import java.util.UUID;

public class PackageWithChecksumListWriter implements ItemWriter<List<List<ExternalPurlRef>>>, StepExecutionListener {
    private static final Logger logger = LoggerFactory.getLogger(PackageWithChecksumListWriter.class);

    private final ChecksumService checksumService;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;


    public PackageWithChecksumListWriter(ChecksumService checksumService) {
        this.checksumService = checksumService;
    }

    public ChecksumService getChecksumService() {
        return checksumService;
    }

    @Override
    public void write(List<? extends List<List<ExternalPurlRef>>> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start PackageWithChecksumListWriter sbomId:{}", sbomId);
        for (List<List<ExternalPurlRef>> externalPurlRefList : chunks) {

            getChecksumService().persistExternalGAVRef(externalPurlRefList);
        }
        logger.info("finish PackageWithChecksumListWriter sbomId:{}", sbomId);
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
