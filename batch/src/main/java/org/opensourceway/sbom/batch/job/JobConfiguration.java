package org.opensourceway.sbom.batch.job;

import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.configuration.JobFactory;
import org.springframework.batch.core.configuration.JobRegistry;
import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
import org.springframework.batch.core.configuration.support.ReferenceJobFactory;
import org.springframework.batch.core.explore.JobExplorer;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.launch.JobOperator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.Objects;

@Configuration
@EnableBatchProcessing
public class JobConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(JobConfiguration.class);

    @Autowired
    private JobRegistry jobRegistry;

    @Autowired
    private JobLauncher jobLauncher;

    @Autowired
    private JobOperator jobOperator;


    @Autowired
    private JobExplorer jobExplorer;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private Job readSbomJob;

    @Autowired
    private RawSbomRepository rawSbomRepository;

    /**
     * jobLauncher.run is synchronized, thread will block until job finish or failure
     */
    public void launchSbomReadJob() throws Exception {
        jobLauncher.run(readSbomJob, new JobParametersBuilder().addLong("startTimestamp", System.currentTimeMillis()).toJobParameters());
    }

    /**
     * jobOperator.restart is synchronized, thread will block until job finish or failure
     */
    public void restartSbomReadJob() throws Exception {
        RawSbom rawSbom = rawSbomRepository.queryOneTaskByTaskStatusWithLock(SbomConstants.TASK_STATUS_FAILED).orElse(null);
        if (Objects.isNull(rawSbom)) {
            logger.info("no failed job need to restart");
            return;
        }
        if (Objects.isNull(rawSbom.getJobExecutionId())) {
            logger.info("find a failed raw sbom id:{}, but job execution id is null", rawSbom.getId());
            rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_FAILED_FINISH);
            rawSbomRepository.save(rawSbom);
            return;
        }

        logger.info("find a failed raw sbom id:{}, job execution id: {}, restart it", rawSbom.getId(), rawSbom.getJobExecutionId());
        if (!jobOperator.getJobNames().contains(readSbomJob.getName())) {
            JobFactory jobFactory = new ReferenceJobFactory(readSbomJob);
            jobRegistry.register(jobFactory);
        }
        jobOperator.restart(rawSbom.getJobExecutionId());
        logger.info("failed raw sbom id:{}, restart finish", rawSbom.getId());
    }

}