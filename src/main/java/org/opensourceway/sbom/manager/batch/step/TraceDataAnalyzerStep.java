package org.opensourceway.sbom.manager.batch.step;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.analyzer.TraceDataAnalyzer;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.batch.ExecutionContextUtils;
import org.opensourceway.sbom.manager.utils.SbomFormat;
import org.opensourceway.sbom.manager.utils.SbomSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

public class TraceDataAnalyzerStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(TraceDataAnalyzerStep.class);

    @Autowired
    private TraceDataAnalyzer traceDataAnalyzer;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        logger.info("start TraceDataAnalyzerStep rawSbomId:{}", rawSbomId);

        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        SbomSpecification specification = (SbomSpecification) jobContext.get(BatchContextConstants.BATCH_SBOM_SPEC_KEY);
        SbomFormat format = (SbomFormat) jobContext.get(BatchContextConstants.BATCH_SBOM_FORMAT_KEY);
        byte[] traceData = (byte[]) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY);
        assert traceData != null;

        byte[] decodedTraceData = Base64.getDecoder().decode(new String(traceData, StandardCharsets.UTF_8));
        logger.info("trace data productName:{}, SbomSpecification:{}, format:{}, decodedTraceData:{}",
                productName, specification, format, decodedTraceData.length);
        byte[] sbomData = traceDataAnalyzer.analyze(productName, new ByteArrayInputStream(decodedTraceData));
        jobContext.put(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY, sbomData);

        logger.info("finish TraceDataAnalyzerStep rawSbomId:{}", rawSbomId);
        return RepeatStatus.FINISHED;
    }
}