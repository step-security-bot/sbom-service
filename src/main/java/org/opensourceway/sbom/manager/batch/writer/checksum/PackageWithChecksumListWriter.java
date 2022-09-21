package org.opensourceway.sbom.manager.batch.writer.checksum;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.service.checksum.ChecksumService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;

import java.util.List;

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
        logger.info("start PackageWithChecksumListWriter service name:{}", getChecksumService().getClass().getName());
        for (List<List<ExternalPurlRef>> externalPurlRefList : chunks) {

            getChecksumService().persistExternalGAVRef(externalPurlRefList);
        }
        logger.info("finish PackageWithChecksumListWriter");
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
