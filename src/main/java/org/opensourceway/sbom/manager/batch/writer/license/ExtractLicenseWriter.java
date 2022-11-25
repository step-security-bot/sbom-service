package org.opensourceway.sbom.manager.batch.writer.license;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.service.license.LicenseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class ExtractLicenseWriter implements ItemWriter<Set<Pair<ExternalPurlRef, Object>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractLicenseWriter.class);

    @Autowired
    @Qualifier("licenseServiceImpl")
    private LicenseService licenseService;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Override
    public void write(List<? extends Set<Pair<ExternalPurlRef, Object>>> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseWriter sbomId:{}, chunk size:{}", sbomId, chunks.size());

        Map<String, List<String>> illegalLicenseInfo = new HashMap<>();
        for (Set<Pair<ExternalPurlRef, Object>> externalLicenseRefSet : chunks) {
            Map<String, List<String>> chunkLicInfo = licenseService.persistExternalLicenseRefChunk(externalLicenseRefSet);
            chunkLicInfo.forEach((pkgName, licList) -> {
                List<String> templist = illegalLicenseInfo.getOrDefault(pkgName, new ArrayList<>());
                templist.addAll(licList);
                illegalLicenseInfo.put(pkgName, templist);
            });
        }
        if (MapUtils.isNotEmpty(illegalLicenseInfo)) {
            logger.warn("illegal licenses info in chunks:{}", illegalLicenseInfo);
        }
        logger.info("finish ExtractLicenseWriter sbomId:{}", sbomId);
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
