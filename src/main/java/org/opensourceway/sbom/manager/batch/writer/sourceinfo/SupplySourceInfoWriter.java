package org.opensourceway.sbom.manager.batch.writer.sourceinfo;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.batch.pojo.SupplySourceInfo;
import org.opensourceway.sbom.manager.dao.FileRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.SbomElementRelationshipRepository;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.model.File;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.SbomElementRelationship;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class SupplySourceInfoWriter implements ItemWriter<SupplySourceInfo>, StepExecutionListener {
    private static final Logger logger = LoggerFactory.getLogger(SupplySourceInfoWriter.class);

    @Autowired
    private SbomRepository sbomRepository;

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
        Assert.isTrue(sbomId != null, "sbomId is dirty");
        logger.info("start SupplySourceInfoWriter sbomId:{}", sbomId);
        Sbom sbom = sbomRepository.findById(sbomId).orElseThrow(() -> new RuntimeException("can't find sbom with id: %s".formatted(sbomId)));
        Set<File> allFileSet = new HashSet<>();
        Set<SbomElementRelationship> allRelationshipSet = new HashSet<>();

        chunks.forEach(sourceInfo -> {
            packageRepository.saveAll(sourceInfo.getPkgList());
            allFileSet.addAll(sourceInfo.getFileList());
            allRelationshipSet.addAll(sourceInfo.getRelationshipList());
        });

        List<File> saveFileList = allFileSet
                .stream()
                .filter(tempFile -> !sbom.getFiles().contains(tempFile))
                .toList();
        logger.info("==current sbom file size:{}, chunk fileSet size:{}, save fileList size:{}", sbom.getFiles().size(), allFileSet.size(), saveFileList.size());
        fileRepository.saveAll(saveFileList);

        List<SbomElementRelationship> saveRelationshipList = allRelationshipSet
                .stream()
                .filter(tempRelationship -> !sbom.getSbomElementRelationships().contains(tempRelationship))
                .toList();
        logger.info("==current sbom relationship size:{}, chunk relationshipSet size:{}, save relationshipList size:{}",
                sbom.getSbomElementRelationships().size(), allRelationshipSet.size(), saveRelationshipList.size());
        elementRelationshipRepository.saveAll(saveRelationshipList);

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
