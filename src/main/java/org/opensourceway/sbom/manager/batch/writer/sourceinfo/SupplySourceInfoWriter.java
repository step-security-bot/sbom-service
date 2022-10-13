package org.opensourceway.sbom.manager.batch.writer.sourceinfo;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.model.Package;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

public class SupplySourceInfoWriter implements ItemWriter<List<Package>>, StepExecutionListener {
    private static final Logger logger = LoggerFactory.getLogger(SupplySourceInfoWriter.class);

    @Autowired
    private PackageRepository packageRepository;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;


    @Override
    public void write(List<? extends List<Package>> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start SupplySourceInfoWriter sbomId:{}", sbomId);

        chunks.forEach(pkgList -> packageRepository.saveAll(pkgList));

        logger.info("finish SupplySourceInfoWriter sbomId:{}", sbomId);
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
