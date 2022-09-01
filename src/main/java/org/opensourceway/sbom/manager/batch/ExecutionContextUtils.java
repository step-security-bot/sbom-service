package org.opensourceway.sbom.manager.batch;

import org.springframework.batch.core.StepContribution;
import org.springframework.batch.item.ExecutionContext;

public class ExecutionContextUtils {

    public static ExecutionContext getJobContext(StepContribution contribution) {
        return contribution.getStepExecution().getJobExecution().getExecutionContext();
    }

}
