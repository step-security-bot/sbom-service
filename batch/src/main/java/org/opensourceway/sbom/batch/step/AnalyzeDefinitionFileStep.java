package org.opensourceway.sbom.batch.step;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.analyzer.SbomContentAnalyzer;
import org.opensourceway.sbom.batch.utils.ExecutionContextUtils;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

public class AnalyzeDefinitionFileStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(AnalyzeDefinitionFileStep.class);

    @Autowired
    @Qualifier("definitionFileAnalyzer")
    private SbomContentAnalyzer definitionFileAnalyzer;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        logger.info("start AnalyzeDefinitionFileStep rawSbomId:{}", rawSbomId);

        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        byte[] data = (byte[]) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY);
        assert data != null;

        byte[] decodedData = Base64.getDecoder().decode(new String(data, StandardCharsets.UTF_8));
        logger.info("AnalyzeDefinitionFile productName:{}, decodedData:{}", productName, decodedData.length);

        byte[] sbomData = definitionFileAnalyzer.analyze(productName, new ByteArrayInputStream(decodedData));
        jobContext.put(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY, sbomData);

        logger.info("finish TraceDataAnalyzerStep rawSbomId:{}", rawSbomId);
        return RepeatStatus.FINISHED;
    }
}