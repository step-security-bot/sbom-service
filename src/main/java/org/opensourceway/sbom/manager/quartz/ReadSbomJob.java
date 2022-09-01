package org.opensourceway.sbom.manager.quartz;

import org.opensourceway.sbom.manager.batch.job.JobConfiguration;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.SchedulerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.PropertyAccessorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

public class ReadSbomJob implements Job {

    private static final Logger logger = LoggerFactory.getLogger(ReadSbomJob.class);

    @Autowired
    private JobConfiguration batchJobConfiguration;

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void execute(JobExecutionContext context) throws JobExecutionException {
        try {
            BeanWrapper bw = PropertyAccessorFactory.forBeanPropertyAccess(this);
            MutablePropertyValues pvs = new MutablePropertyValues();
            pvs.addPropertyValues(context.getScheduler().getContext());
            pvs.addPropertyValues(context.getMergedJobDataMap());
            bw.setPropertyValues(pvs, true);
        } catch (SchedulerException ex) {
            throw new JobExecutionException(ex);
        }
        executeInternal(context);
    }

    protected void executeInternal(JobExecutionContext quartzJobContext) {
        logger.info("start launch sbom read job");
        try {
            batchJobConfiguration.launchSbomReadJob();
        } catch (Exception e) {
            logger.error("launch sbom read job failed", e);
        }
        logger.info("finish launch sbom read job");
    }

}
