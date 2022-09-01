package org.opensourceway.sbom.manager.batch.step;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.analyzer.TraceDataAnalyzer;
import org.opensourceway.sbom.manager.utils.SbomFormat;
import org.opensourceway.sbom.manager.utils.SbomSpecification;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.batch.ExecutionContextUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;

public class TraceDataAnalyzerStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(TraceDataAnalyzerStep.class);

    @Autowired
    private TraceDataAnalyzer traceDataAnalyzer;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        logger.info("start TraceDataAnalyzerStep");
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);

        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        SbomSpecification specification = (SbomSpecification) jobContext.get(BatchContextConstants.BATCH_SBOM_SPEC_KEY);
        SbomFormat format = (SbomFormat) jobContext.get(BatchContextConstants.BATCH_SBOM_FORMAT_KEY);
        byte[] traceData = (byte[]) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY);
        assert traceData != null;

        // TODO unfinished logic
        logger.info("trace data productName:{}, SbomSpecification:{}, format:{}, traceData:{}", productName, specification, format, traceData.length);
        // byte[] sbomData = traceDataAnalyzer.analyze(productName, traceData);
        // ExecutionContextUtils.getExecutionContext(contribution).put(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY,sbomData);

        logger.info("finish TraceDataAnalyzerStep");
        return RepeatStatus.FINISHED;
    }
}