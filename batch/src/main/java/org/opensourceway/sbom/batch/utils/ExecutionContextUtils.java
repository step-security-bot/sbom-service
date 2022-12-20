package org.opensourceway.sbom.batch.utils;

import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.item.ExecutionContext;

public class ExecutionContextUtils {

    public static ExecutionContext getJobContext(StepContribution contribution) {
        return contribution.getStepExecution().getJobExecution().getExecutionContext();
    }

    public static JobExecution getJobExecution(StepContribution contribution) {
        return contribution.getStepExecution().getJobExecution();
    }

}
