package org.opensourceway.sbom.batch.reader.sourceinfo;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.BatchFlowExecConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ChunkListener;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.item.Chunk;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

public class SupplySourceInfoReader implements ItemReader<List<UUID>>, StepExecutionListener, ChunkListener {

    private static final Logger logger = LoggerFactory.getLogger(SupplySourceInfoReader.class);

    private static final List<String> SUPPLY_SOURCE_INFO_PRODUCT_TYPES = List.of(
            SbomConstants.PRODUCT_OPENEULER_NAME, SbomConstants.PRODUCT_OPENHARMONY_NAME);

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private ProductRepository productRepository;

    private List<List<UUID>> chunks = null;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    private ChunkContext chunkContext;

    private void initMapper(UUID sbomId) {
        if (sbomId == null) {
            logger.warn("sbom id is mull");
            return;
        }

        Product product = productRepository.findBySbomId(sbomId);
        String productType = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY);
        if (SUPPLY_SOURCE_INFO_PRODUCT_TYPES.stream().noneMatch(it -> StringUtils.equalsIgnoreCase(it, productType))) {
            logger.info("SupplySourceInfoReader skip, productType is:{}, sbomId:{}", productType, sbomId);
            return;
        }
        this.stepExecution.getExecutionContext().putString(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY,
                String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY)));

        List<UUID> pkgList = packageRepository.findBySbomId(sbomId)
                .stream()
                .map(Package::getId)
                .toList();

        if (CollectionUtils.isEmpty(pkgList)) {
            logger.error("sbomId:{} `s package list is empty", sbomId);
            return;
        }

        this.chunks = ListUtils.partition(pkgList, BatchFlowExecConstants.COMMON_CHUNK_BULK_REQUEST_SIZE)
                .stream()
                .map(ArrayList::new)
                .collect(Collectors.toCollection(CopyOnWriteArrayList::new));

        // restore chunks to previous operator, then partial retry
        int remainingSize = stepExecution.getExecutionContext().getInt(BatchContextConstants.BATCH_READER_STEP_REMAINING_SIZE_KEY, 0);
        if (remainingSize > 0 && remainingSize < this.chunks.size()) {
            this.chunks = this.chunks.subList(this.chunks.size() - remainingSize, this.chunks.size());
        }
        logger.info("SupplySourceInfoReader:{} use sbomId:{}, get package chunks size:{}",
                this,
                sbomId,
                this.chunks.size());
    }

    @Nullable
    @Override
    public List<UUID> read() {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start SupplySourceInfoReader sbomId:{}", sbomId);
        if (this.chunks == null) {
            initMapper(sbomId);
        }

        if (CollectionUtils.isEmpty(this.chunks)) {
            return null; // end of the chunks loops
        }
        return this.chunks.remove(0);
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        Assert.isTrue(this.stepExecution == null, "StepExecution is dirty");
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        if (ObjectUtils.isEmpty(this.chunks)) {
            return null;
        }

        int remainingSize = this.chunks.size();

        if (StringUtils.equals(ExitStatus.FAILED.getExitCode(), stepExecution.getExitStatus().getExitCode())
                && this.chunkContext.hasAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_KEY)
                && this.chunkContext.hasAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_INPUT_KEY)) {
            Chunk<List<UUID>> retryInputs = (Chunk<List<UUID>>) this.chunkContext.getAttribute(BatchContextConstants.BUILD_IN_BATCH_CHUNK_FAILED_INPUT_KEY);
            assert retryInputs != null;
            remainingSize += CollectionUtils.size(retryInputs.getItems());
            logger.info("restore failed chunks, job id:{}, remain chunk size:{}, failed chunks size:{}, first element pkg id:{}",
                    stepExecution.getJobExecution().getId(),
                    this.chunks.size(),
                    retryInputs.getItems().size(),
                    retryInputs.getItems().stream().findFirst().map(list -> list.get(0)).map(UUID::toString).orElse(""));
        }

        stepExecution.getExecutionContext().putInt(BatchContextConstants.BATCH_READER_STEP_REMAINING_SIZE_KEY, remainingSize);
        return null;
    }

    @Override
    public void beforeChunk(@NotNull ChunkContext chunkContext) {
        if (this.chunkContext == null) {
            this.chunkContext = chunkContext;
        } else {
            Assert.isTrue(StringUtils.equals(this.chunkContext.getStepContext().getId(), chunkContext.getStepContext().getId()), "ChunkContext is dirty");
        }
    }

    @Override
    public void afterChunk(@NotNull ChunkContext chunkContext) {
    }

    @Override
    public void afterChunkError(@NotNull ChunkContext chunkContext) {
    }

}
