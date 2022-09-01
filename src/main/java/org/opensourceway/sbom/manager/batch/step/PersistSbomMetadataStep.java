package org.opensourceway.sbom.manager.batch.step;

import org.jetbrains.annotations.NotNull;
import org.openeuler.sbom.manager.SbomApplicationContextHolder;
import org.openeuler.sbom.manager.dao.RawSbomRepository;
import org.openeuler.sbom.manager.dao.SbomRepository;
import org.openeuler.sbom.manager.model.Sbom;
import org.openeuler.sbom.manager.model.sbom.SbomDocument;
import org.openeuler.sbom.manager.service.reader.SbomReader;
import org.openeuler.sbom.manager.utils.SbomSpecification;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.batch.ExecutionContextUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

public class PersistSbomMetadataStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(PersistSbomMetadataStep.class);

    @Autowired
    private RawSbomRepository rawSbomRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        logger.info("start PersistSbomMetadataStep");
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);

        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        SbomSpecification specification = (SbomSpecification) jobContext.get(BatchContextConstants.BATCH_SBOM_SPEC_KEY);
        SbomDocument sbomDocument = (SbomDocument) jobContext.get(BatchContextConstants.BATCH_SBOM_DOCUMENT_KEY);
        logger.info("sbom metadata productName:{}, SbomSpecification:{}", productName, specification);

        // delete all data of old sbom
        sbomRepository.findByProductName(productName).ifPresent(sbom -> sbomRepository.delete(sbom));

        // store new sbom
        SbomReader sbomReader = SbomApplicationContextHolder.getSbomReader(specification != null ? specification.getSpecification() : null);
        Sbom sbom = sbomReader.persistSbom(productName, sbomDocument);

        // update task status
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        rawSbomRepository.findById(rawSbomId).ifPresent(rawSbom -> {
            rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_FINISH_PARSE);
            rawSbomRepository.save(rawSbom);
        });

        // update context
        jobContext.put(BatchContextConstants.BATCH_SBOM_ID_KEY, sbom.getId());
        jobContext.remove(BatchContextConstants.BATCH_SBOM_DOCUMENT_KEY);
        logger.info("finish PersistSbomMetadataStep, sbom id:{}", sbom.getId().toString());
        return RepeatStatus.FINISHED;
    }

}
