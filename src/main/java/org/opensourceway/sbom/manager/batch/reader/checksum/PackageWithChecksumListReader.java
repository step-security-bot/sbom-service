package org.opensourceway.sbom.manager.batch.reader.checksum;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.service.checksum.ChecksumService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class PackageWithChecksumListReader implements ItemReader<Package>, StepExecutionListener {
    private static final Logger logger =
            LoggerFactory.getLogger(org.opensourceway.sbom.manager.batch.reader.checksum.PackageWithChecksumListReader.class);
    private final ChecksumService checksumService;

    @Autowired
    SbomRepository sbomRepository;

    private Iterator<Package> iterator = null;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;

    public PackageWithChecksumListReader(ChecksumService checksumService) {
        this.checksumService = checksumService;
    }

    public ChecksumService getChecksumService() {
        return checksumService;
    }

    private void initMapper() {
        if (!getChecksumService().needRequest()) {
            logger.warn("sonaType client does not request");
            return;
        }

        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;

        if (sbomId == null) {
            logger.warn("sbom id is mull");
            return;
        }
        Optional<Sbom> sbomOptional = sbomRepository.findById(sbomId);
        if (sbomOptional.isEmpty()) {
            logger.error("sbomId:{} is not exists", sbomId);
            return;
        }

        List<Package> packages =
                sbomOptional.get().getPackages().stream().filter(pkg ->
                        pkg.getExternalPurlRefs().stream().anyMatch(externalPurlRef ->
                                "checksum".equals(externalPurlRef.getType()))).toList();

        this.iterator = packages.iterator();
        logger.info("PackageWithChecksumListReader use sbomId:{}, get packages size:{}",
                sbomId,
                packages.size());

    }

    @Nullable
    @Override
    public Package read() {
        if (iterator == null) {
            initMapper();
        }
        logger.info("start PackageWithChecksumListReader");

        if (iterator != null && iterator.hasNext())
            return iterator.next();
        else
            return null; // end of data
    }

    @Override
    public void beforeStep(@NotNull StepExecution stepExecution) {
        this.stepExecution = stepExecution;
        this.jobContext = this.stepExecution.getJobExecution().getExecutionContext();
        this.iterator = null;
    }

    @Override
    public ExitStatus afterStep(@NotNull StepExecution stepExecution) {
        return null;
    }

}
