package org.opensourceway.sbom.batch.step;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.reader.SbomReader;
import org.opensourceway.sbom.batch.utils.ExecutionContextUtils;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.enums.SbomSpecification;
import org.opensourceway.sbom.model.sbom.SbomDocument;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
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
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        logger.info("start PersistSbomMetadataStep rawSbomId:{}", rawSbomId);

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
        rawSbomRepository.findById(rawSbomId).ifPresent(rawSbom -> {
            rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_FINISH_PARSE);
            rawSbomRepository.save(rawSbom);
        });

        // update context
        jobContext.put(BatchContextConstants.BATCH_SBOM_ID_KEY, sbom.getId());
        jobContext.remove(BatchContextConstants.BATCH_SBOM_DOCUMENT_KEY);
        logger.info("finish PersistSbomMetadataStep rawSbomId:{}, sbom id:{}", rawSbomId, sbom.getId().toString());
        return RepeatStatus.FINISHED;
    }

}
