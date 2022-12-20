package org.opensourceway.sbom.batch.listener;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.BatchStatus;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobExecutionListener;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.launch.JobOperator;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

public class AllStepsListener implements JobExecutionListener {

    private final Integer batchJobRestartMaxTimes;

    @Autowired
    private JobRepository jobRepository;

    @Autowired
    private JobOperator jobOperator;

    @Autowired
    private RawSbomRepository rawSbomRepository;

    private static final Logger logger = LoggerFactory.getLogger(AllStepsListener.class);

    public AllStepsListener(Integer batchJobRestartMaxTimes) {
        this.batchJobRestartMaxTimes = batchJobRestartMaxTimes;
        logger.info("Spring Batch AllStepsListener init, batchJobRestartMaxTimes: {}", batchJobRestartMaxTimes);
    }

    @Override
    public void beforeJob(@NotNull JobExecution jobExecution) {
        logger.info("Start AllStepsListener[beforeJob]");
        try {
            if (!jobExecution.getExecutionContext().containsKey(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY)) {
                // first start
                return;
            }
            UUID rawSbomId = (UUID) jobExecution.getExecutionContext().get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
            RawSbom rawSbom = rawSbomRepository.findById(rawSbomId)
                    .orElseThrow(() -> new RuntimeException("can't rawSbom metadata for %s".formatted(rawSbomId)));

            if (StringUtils.equalsIgnoreCase(rawSbom.getTaskStatus(), SbomConstants.TASK_STATUS_FAILED)) {
                updateJobRestartInfoBeforeJob(rawSbom, jobExecution);
            }
        } catch (Exception e) {
            logger.error("AllStepsListener[beforeJob] Error.", e);
        }

        logger.info("Finish AllStepsListener[beforeJob]");
    }

    @Override
    public void afterJob(@NotNull JobExecution jobExecution) {
        logger.info("Start AllStepsListener[afterJob]");
        try {
            if (!jobExecution.getExecutionContext().containsKey(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY)) {
                return;
            }
            UUID rawSbomId = (UUID) jobExecution.getExecutionContext().get(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY);
            RawSbom rawSbom = rawSbomRepository.findById(rawSbomId)
                    .orElseThrow(() -> new RuntimeException("can't rawSbom metadata for %s".formatted(rawSbomId)));

            dealFailedJob(rawSbom, jobExecution);
        } catch (Exception e) {
            logger.error("AllStepsListener[afterJob] Error.", e);
        }
        logger.info("Finish AllStepsListener[afterJob]");
    }

    private void updateJobRestartInfoBeforeJob(RawSbom rawSbom, JobExecution jobExecution) {
        // update rawSbom taskStatus & jobExecutionId
        boolean isFinishParse = jobRepository.getStepExecutionCount(jobExecution.getJobInstance(), "resolveMavenDepTask") > 0;
        rawSbom.setTaskStatus(isFinishParse ? SbomConstants.TASK_STATUS_FINISH_PARSE : SbomConstants.TASK_STATUS_RUNNING);
        rawSbom.setJobExecutionId(jobExecution.getId());
        rawSbomRepository.save(rawSbom);

        // record restart times in context
        jobExecution.getExecutionContext().putInt(BatchContextConstants.BATCH_JOB_RESTART_COUNTER_KEY,
                jobExecution.getExecutionContext().getInt(BatchContextConstants.BATCH_JOB_RESTART_COUNTER_KEY, 0) + 1);
        logger.info("Finish updateJobRestartInfoBeforeJob");
    }

    private void dealFailedJob(RawSbom rawSbom, JobExecution jobExecution) {
        if (jobExecution.getStatus() == BatchStatus.FAILED) {
            logger.error("batch job instance id:{} failed, rawSbomId:{}, exitStatus:{}",
                    jobExecution.getJobId(),
                    rawSbom.getId(),
                    jobExecution.getExitStatus());

            for (StepExecution stepExecution : jobExecution.getStepExecutions()) {
                if (stepExecution.getStatus() == BatchStatus.FAILED) {
                    logger.error("batch job instance id:{} failed, failed step Name:{}, failureExceptions:{}",
                            jobExecution.getJobId(),
                            stepExecution.getStepName(),
                            stepExecution.getFailureExceptions());
                }
            }

            boolean isOverMaxRestartLimit = jobExecution.getExecutionContext()
                    .getInt(BatchContextConstants.BATCH_JOB_RESTART_COUNTER_KEY, 0) >= this.batchJobRestartMaxTimes;
            logger.error("failed batch job isOverMaxRestartLimit:{}", isOverMaxRestartLimit);
            rawSbom.setTaskStatus(isOverMaxRestartLimit ? SbomConstants.TASK_STATUS_FAILED_FINISH : SbomConstants.TASK_STATUS_FAILED);
            rawSbomRepository.save(rawSbom);
        }
    }

}
