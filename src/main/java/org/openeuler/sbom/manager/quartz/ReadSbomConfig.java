package org.openeuler.sbom.manager.quartz;

import org.quartz.CronScheduleBuilder;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ReadSbomConfig {

    @Bean
    public JobDetail jobDetail() {
        return JobBuilder.newJob(ReadSbomJob.class)
                .withIdentity("readSbom")
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger trigger() {
        return TriggerBuilder.newTrigger()
                .forJob(jobDetail())
                .withIdentity("readSbom")
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule("0 * * * * ? *"))
                .build();
    }

}
