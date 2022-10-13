package org.opensourceway.sbom.manager.batch.processor.sourceinfo;

import org.apache.commons.collections4.CollectionUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.UUID;

public class SupplySourceInfoProcessor implements ItemProcessor<List<Package>, List<Package>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(SupplySourceInfoProcessor.class);
    @Autowired
    private RepoMetaRepository repoMetaRepository;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Nullable
    @Override
    public List<Package> process(List<Package> pkgList) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        String productVersion = stepExecution.getExecutionContext().getString(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY);
        logger.info("start SupplySourceInfoProcessor sbomId:{}, productVersion:{}, first pkg id:{}", sbomId, productVersion, pkgList.get(0).getId().toString());

        pkgList.forEach(pkg -> {
            try {
                List<RepoMeta> repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(SbomConstants.PRODUCT_OPENEULER_NAME,
                        productVersion,
                        pkg.getName());
                if (CollectionUtils.isNotEmpty(repoMetaList)) {
                    pkg.setDownloadLocation(repoMetaList.get(0).getDownloadLocation());
                } else {
                    logger.error("SupplySourceInfoStep can't find package's repoMeta, sbomId:{}, pkgName:{}, branch:{}",
                            sbomId,
                            pkg.getName(),
                            productVersion);
                }
                // TODO completed fo openEuler upstream,patch info
            } catch (Exception e) {
                logger.error("SupplySourceInfoProcessor failed, package id:{}, package name:{}", pkg.getId(), pkg.getName(), e);
                throw new RuntimeException(e);
            }
        });

        logger.info("finish SupplySourceInfoProcessor sbomId:{}", sbomId);
        return pkgList;
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        return null;
    }
}
