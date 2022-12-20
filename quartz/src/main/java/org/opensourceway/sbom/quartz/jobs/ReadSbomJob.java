package org.opensourceway.sbom.quartz.jobs;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.batch.job.JobConfiguration;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

public class ReadSbomJob extends QuartzJobBean {

    private static final Logger logger = LoggerFactory.getLogger(ReadSbomJob.class);

    @Autowired
    private JobConfiguration batchJobConfiguration;

    protected void executeInternal(@NotNull JobExecutionContext quartzJobContext) {
        logger.info("start launch sbom read job");
        try {
            batchJobConfiguration.launchSbomReadJob();
        } catch (Exception e) {
            logger.error("launch sbom read job failed", e);
        }
        logger.info("finish launch sbom read job");
    }

}
