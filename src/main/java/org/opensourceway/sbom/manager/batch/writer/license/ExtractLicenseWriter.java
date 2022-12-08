package org.opensourceway.sbom.manager.batch.writer.license;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.dao.LicenseRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
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
import java.util.Set;
import java.util.UUID;

public class ExtractLicenseWriter implements ItemWriter<List<Pair<Package, License>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractLicenseWriter.class);

    @Autowired
    @Qualifier("licenseServiceImpl")
    private LicenseService licenseService;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private PackageRepository packageRepository;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    private void persistExternalLicenseRefChunk(Set<Package> packageSetToSave, Set<License> licenseSetToSave) {
        licenseRepository.saveAll(licenseSetToSave);
        packageRepository.saveAll(packageSetToSave);
    }

    @Override
    public void write(List<? extends List<Pair<Package, License>>> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseWriter sbomId:{}, chunk size:{}", sbomId, chunks.size());
        Set<Package> packageSetToSave = new HashSet<>();
        Set<License> licenseSetToSave = new HashSet<>();
        for (List<Pair<Package, License>> licenseAndPkgListToSave : chunks) {
            for (Pair<Package, License> pair : licenseAndPkgListToSave) {
                packageSetToSave.add(pair.getLeft());
                licenseSetToSave.add(pair.getRight());
            }
        }
        persistExternalLicenseRefChunk(packageSetToSave, licenseSetToSave);
        stepExecution.getExecutionContext().put(BatchContextConstants.BATCH_STEP_LICENSE_MAP_KEY, new HashMap<>());
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
