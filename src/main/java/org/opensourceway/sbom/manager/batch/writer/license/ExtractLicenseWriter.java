package org.opensourceway.sbom.manager.batch.writer.license;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
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

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class ExtractLicenseWriter implements ItemWriter<List<Pair<Package, License>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractLicenseWriter.class);

    @Autowired
    @Qualifier("licenseServiceImpl")
    private LicenseService licenseService;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Override
    public void write(List<? extends List<Pair<Package, License>>> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseWriter sbomId:{}, chunk size:{}", sbomId, chunks.size());
        Set<Package> packageSetToSave = new HashSet<>();
        Map<String, License> spdxLicenseIdMap = new HashMap<>();
        for (List<Pair<Package, License>> licenseAndPkgListToSave : chunks) {
            for (Pair<Package, License> pair : licenseAndPkgListToSave) {
                packageSetToSave.add(pair.getLeft());
                String spdxLicenseId = pair.getRight().getSpdxLicenseId();
                if (spdxLicenseIdMap.containsKey(spdxLicenseId)) {
                    spdxLicenseIdMap.get(spdxLicenseId).getPackages().addAll(pair.getRight().getPackages());
                } else {
                    spdxLicenseIdMap.put(spdxLicenseId, pair.getRight());
                }
            }
        }
        Set<License> licenseSetToSave = new HashSet<>(spdxLicenseIdMap.values());
        licenseService.persistExternalLicenseRefChunk(Pair.of(packageSetToSave, licenseSetToSave));
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
