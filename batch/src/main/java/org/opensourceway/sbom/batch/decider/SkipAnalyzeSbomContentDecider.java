package org.opensourceway.sbom.batch.decider;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.BatchFlowExecConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.job.flow.FlowExecutionStatus;
import org.springframework.batch.core.job.flow.JobExecutionDecider;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.UUID;

public class SkipAnalyzeSbomContentDecider implements JobExecutionDecider {

    private final static Logger logger = LoggerFactory.getLogger(SkipAnalyzeSbomContentDecider.class);

    private final static List<String> NEED_ANALYZE_TRACE_DATA_PRODUCT_LIST = List.of(
            SbomConstants.PRODUCT_MINDSPORE_NAME.toLowerCase(),
            SbomConstants.PRODUCT_OPENGAUSS_NAME.toLowerCase());

    private final static List<String> NEED_ANALYZE_DEFINITION_FILE_PRODUCT_LIST = List.of(
            SbomConstants.PRODUCT_OPENHARMONY_NAME.toLowerCase(), SbomConstants.PRODUCT_MAJUN_NAME.toLowerCase());

    @NotNull
    @Override
    public FlowExecutionStatus decide(JobExecution jobExecution, @Nullable StepExecution stepExecution) {
        ExecutionContext jobContext = jobExecution.getExecutionContext();
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        logger.info("start SkipAnalyzeTraceDataDecider rawSbomId:{}, productName:{}", rawSbomId, productName);

        if (NEED_ANALYZE_TRACE_DATA_PRODUCT_LIST.contains(jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY).toLowerCase())) {
            logger.info("SkipAnalyzeTraceDataDecider to inorder trace data, rawSbomId:{}", rawSbomId);
            return new FlowExecutionStatus(BatchFlowExecConstants.FLOW_EXECUTION_STATUS_OF_INORDER_TRACE_DATA);
        } else if (NEED_ANALYZE_DEFINITION_FILE_PRODUCT_LIST.contains(jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY).toLowerCase())) {
            logger.info("SkipAnalyzeTraceDataDecider to inorder definition file, rawSbomId:{}", rawSbomId);
            return new FlowExecutionStatus(BatchFlowExecConstants.FLOW_EXECUTION_STATUS_OF_INORDER_DEFINITION_FILE);
        } else {
            logger.info("SkipAnalyzeTraceDataDecider to skip, rawSbomId:{}", rawSbomId);
            return new FlowExecutionStatus(BatchFlowExecConstants.FLOW_EXECUTION_STATUS_OF_SKIP);
        }
    }
}
