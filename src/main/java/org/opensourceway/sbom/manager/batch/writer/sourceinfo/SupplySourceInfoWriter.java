package org.opensourceway.sbom.manager.batch.writer.sourceinfo;

import org.apache.commons.collections4.CollectionUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.batch.pojo.SupplySourceInfo;
import org.opensourceway.sbom.manager.dao.FileRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.SbomElementRelationshipRepository;
import org.opensourceway.sbom.manager.model.File;
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

public class SupplySourceInfoWriter implements ItemWriter<SupplySourceInfo>, StepExecutionListener {
    private static final Logger logger = LoggerFactory.getLogger(SupplySourceInfoWriter.class);

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private FileRepository fileRepository;

    @Autowired
    private SbomElementRelationshipRepository elementRelationshipRepository;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Override
    public void write(List<? extends SupplySourceInfo> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start SupplySourceInfoWriter sbomId:{}", sbomId);

        chunks.forEach(sourceInfo -> {
            packageRepository.saveAll(sourceInfo.getPkgList());

            List<File> fileList = sourceInfo.getFileList().stream().distinct().toList();
            if (CollectionUtils.size(sourceInfo.getFileList()) != CollectionUtils.size(fileList)) {
                logger.warn("SupplySourceInfoWriter get fileList size:{}, distinct size:{}",
                        CollectionUtils.size(sourceInfo.getFileList()),
                        CollectionUtils.size(fileList));
            }

            fileList.forEach(file ->
                    fileRepository.findBySbomIdAndSpdxId(file.getSbom().getId(), file.getSpdxId())
                            .stream()
                            .findAny()
                            .ifPresentOrElse(existFile -> logger.debug("SupplySourceInfoWriter sbom file:{} has existed in sbom:{} ", file.getFileName(), file.getSbom().getId()),
                                    () -> fileRepository.save(file)));

            elementRelationshipRepository.saveAll(sourceInfo.getRelationshipList());
        });

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
