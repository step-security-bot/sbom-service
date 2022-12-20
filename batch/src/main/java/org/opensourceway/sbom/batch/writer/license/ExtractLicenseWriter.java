package org.opensourceway.sbom.batch.writer.license;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.license.LicenseService;
import org.opensourceway.sbom.dao.LicenseRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgLicenseRelp;
import org.opensourceway.sbom.model.pojo.vo.license.ExtractLicenseVo;
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
import java.util.function.Function;
import java.util.stream.Collectors;

public class ExtractLicenseWriter implements ItemWriter<ExtractLicenseVo>, StepExecutionListener {

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

    @Override
    public void write(List<? extends ExtractLicenseVo> chunks) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseWriter sbomId:{}, chunk size:{}", sbomId, chunks.size());
        Set<Package> packageSetToSave = new HashSet<>();
        Set<License> licenseSetToSave = new HashSet<>();
        Map<PkgLicenseRelp, String> licenseOfRelp = new HashMap<>();
        for (ExtractLicenseVo vo : chunks) {
            packageSetToSave.addAll(vo.getPackages());
            licenseSetToSave.addAll(vo.getLicenses());
            licenseOfRelp.putAll(vo.getLicenseOfRelp());
        }
        persistExternalLicenseRefChunk(packageSetToSave, licenseSetToSave, licenseOfRelp);
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

    private void persistExternalLicenseRefChunk(Set<Package> packageSetToSave, Set<License> licenseSetToSave,
                                                Map<PkgLicenseRelp, String> licenseOfRelp) {
        Map<String, License> savedLicenses = licenseRepository.saveAll(licenseSetToSave).stream()
                .collect(Collectors.toMap(License::getSpdxLicenseId, Function.identity()));
        packageSetToSave.forEach(pkg -> pkg.getPkgLicenseRelps()
                .forEach(relp -> relp.setLicense(savedLicenses.get(licenseOfRelp.get(relp)))));
        packageRepository.saveAll(packageSetToSave);
    }
}
