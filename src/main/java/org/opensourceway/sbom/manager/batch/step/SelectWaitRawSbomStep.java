package org.opensourceway.sbom.manager.batch.step;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.RawSbomRepository;
import org.opensourceway.sbom.manager.model.RawSbom;
import org.opensourceway.sbom.manager.utils.SbomFormat;
import org.opensourceway.sbom.manager.utils.SbomSpecification;
import org.opensourceway.sbom.manager.batch.ExecutionContextUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Objects;

public class SelectWaitRawSbomStep implements Tasklet {

    private static final Logger logger = LoggerFactory.getLogger(SelectWaitRawSbomStep.class);

    @Autowired
    private RawSbomRepository rawSbomRepository;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        logger.info("start SelectWaitRawSbomStep, try to find a waiting raw sbom");
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);

        RawSbom rawSbom = rawSbomRepository.queryOneTaskByTaskStatusWithLock(SbomConstants.TASK_STATUS_WAIT).orElse(null);
        if (Objects.isNull(rawSbom)) {
            logger.info("not find waiting raw sbom");
            contribution.setExitStatus(ExitStatus.STOPPED);
        } else {
            logger.info("find a waiting raw sbom, id:{}", rawSbom.getId());
            rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_RUNNING);
            rawSbom.setJobExecutionId(ExecutionContextUtils.getJobExecution(contribution).getId());
            rawSbomRepository.save(rawSbom);

            jobContext.put(BatchContextConstants.BATCH_RAW_SBOM_ID_KEY, rawSbom.getId());
            jobContext.putString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY, rawSbom.getProduct().getName());
            jobContext.putString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY,
                    String.valueOf(rawSbom.getProduct().getAttribute().get(BatchContextConstants.BATCH_PRODUCT_TYPE_KEY)));
            jobContext.put(BatchContextConstants.BATCH_RAW_SBOM_BYTES_KEY, rawSbom.getValue());

            SbomSpecification specification = SbomSpecification.findSpecification(rawSbom.getSpec(), rawSbom.getSpecVersion());
            jobContext.put(BatchContextConstants.BATCH_SBOM_SPEC_KEY, specification);

            SbomFormat format = SbomFormat.findSbomFormat(rawSbom.getFormat());
            jobContext.put(BatchContextConstants.BATCH_SBOM_FORMAT_KEY, format);

            contribution.setExitStatus(ExitStatus.COMPLETED);
        }
        logger.info("finish SelectWaitRawSbomStep");
        return RepeatStatus.FINISHED;
    }
}