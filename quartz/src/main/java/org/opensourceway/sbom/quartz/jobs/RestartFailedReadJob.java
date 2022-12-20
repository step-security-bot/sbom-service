package org.opensourceway.sbom.quartz.jobs;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.batch.job.JobConfiguration;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

public class RestartFailedReadJob extends QuartzJobBean {

    private static final Logger logger = LoggerFactory.getLogger(RestartFailedReadJob.class);

    @Autowired
    private JobConfiguration batchJobConfiguration;

    protected void executeInternal(@NotNull JobExecutionContext quartzJobContext) {
        logger.info("start launch restart-sbom-failed-read job");
        try {
            batchJobConfiguration.restartSbomReadJob();
        } catch (Exception e) {
            logger.error("launch restart-sbom-failed-read job failed", e);
        }
        logger.info("finish launch restart-sbom-failed-read job");
    }

}
