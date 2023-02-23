package org.opensourceway.sbom.batch.decider;

import org.apache.commons.lang3.StringUtils;
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

import java.util.UUID;

public class OpenHarmonySpecialTaskDecider implements JobExecutionDecider {

    private final static Logger logger = LoggerFactory.getLogger(OpenHarmonySpecialTaskDecider.class);

    @NotNull
    @Override
    public FlowExecutionStatus decide(@NotNull JobExecution jobExecution, StepExecution stepExecution) {
        ExecutionContext jobContext = jobExecution.getExecutionContext();
        UUID rawSbomId = (UUID) jobContext.get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
        String productType = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY);
        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);

        if (!StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)) {
            logger.info("Skip non-OpenHarmony product, rawSbomId:{}", rawSbomId);
            return new FlowExecutionStatus(BatchFlowExecConstants.FLOW_EXECUTION_STATUS_OF_SKIP);
        }
        logger.info("Execute special task for OpenHarmony product: {}", productName);
        return new FlowExecutionStatus(BatchFlowExecConstants.FLOW_EXECUTION_STATUS_OF_OPENHARMONY_SPECIAL_TASK);
    }
}
