package org.openeuler.sbom.manager.quartz;

import org.openeuler.sbom.manager.SbomApplicationContextHolder;
import org.openeuler.sbom.manager.constant.SbomConstants;
import org.openeuler.sbom.manager.dao.RawSbomRepository;
import org.openeuler.sbom.manager.model.RawSbom;
import org.openeuler.sbom.manager.service.reader.SbomReader;
import org.openeuler.sbom.manager.utils.SbomFormat;
import org.openeuler.sbom.manager.utils.SbomSpecification;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Objects;

public class ReadSbomJob extends QuartzJobBean {

    private static final Logger logger = LoggerFactory.getLogger(ReadSbomJob.class);

    @Autowired
    private RawSbomRepository rawSbomRepository;

    @Override
    @Transactional(rollbackFor = Exception.class)
    protected void executeInternal(JobExecutionContext context) throws JobExecutionException {
        logger.info("quartz job: try to find a waiting raw sbom");

        RawSbom rawSbom = rawSbomRepository.queryOneWaitingTaskWithLock().orElse(null);
        if (Objects.isNull(rawSbom)) {
            return;
        }

        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_RUNNING);
        rawSbomRepository.save(rawSbom);

        logger.info("quartz job: find a waiting raw sbom with id [{}], product name [{}]", rawSbom.getId(), rawSbom.getProduct().getName());
        SbomSpecification specification = SbomSpecification.findSpecification(rawSbom.getSpec(), rawSbom.getSpecVersion());
        SbomReader sbomReader = SbomApplicationContextHolder.getSbomReader(specification != null ? specification.getSpecification() : null);
        // TODO: move the following logic to spring-batch, and separately set task status to 'finish_parse' and 'finish'
        try {
            sbomReader.read(rawSbom.getProduct().getName(), SbomFormat.findSbomFormat(rawSbom.getFormat()), rawSbom.getValue());
        } catch (IOException e) {
            throw new JobExecutionException(e);
        }

        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_FINISH);
        rawSbomRepository.save(rawSbom);
        logger.info("quartz job: end to read raw sbom with id [{}], product name [{}]", rawSbom.getId(), rawSbom.getProduct().getName());
    }
}
