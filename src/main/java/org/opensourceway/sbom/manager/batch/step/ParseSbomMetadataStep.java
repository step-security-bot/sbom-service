package org.opensourceway.sbom.manager.batch.step;

import org.jetbrains.annotations.NotNull;
import org.openeuler.sbom.manager.SbomApplicationContextHolder;
import org.openeuler.sbom.manager.model.sbom.SbomDocument;
import org.openeuler.sbom.manager.service.reader.SbomReader;
import org.openeuler.sbom.manager.utils.SbomFormat;
import org.openeuler.sbom.manager.utils.SbomSpecification;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.batch.ExecutionContextUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;

public class ParseSbomMetadataStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(ParseSbomMetadataStep.class);

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) throws Exception {
        logger.info("start ParseSbomMetadataStep");
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);

        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        SbomSpecification specification = (SbomSpecification) jobContext.get(BatchContextConstants.BATCH_SBOM_SPEC_KEY);
        SbomFormat format = (SbomFormat) jobContext.get(BatchContextConstants.BATCH_SBOM_FORMAT_KEY);
        byte[] fileContent = (byte[]) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY);
        assert fileContent != null;
        logger.info("sbom metadata productName:{}, SbomSpecification:{}, format:{}, traceData:{}", productName, specification, format, fileContent.length);

        SbomReader sbomReader = SbomApplicationContextHolder.getSbomReader(specification != null ? specification.getSpecification() : null);
        SbomDocument document = sbomReader.readToDocument(productName, format, fileContent);
        jobContext.put(BatchContextConstants.BATCH_SBOM_DOCUMENT_KEY, document);
        jobContext.remove(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY);

        logger.info("finish ParseSbomMetadataStep");
        return RepeatStatus.FINISHED;
    }

}
