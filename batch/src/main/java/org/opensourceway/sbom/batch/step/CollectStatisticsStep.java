package org.opensourceway.sbom.batch.step;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.batch.utils.ExecutionContextUtils;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PackageStatistics;
import org.opensourceway.sbom.model.entity.PkgLicenseRelp;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductStatistics;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.enums.CvssSeverity;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ObjectUtils;

import java.sql.Timestamp;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

public class CollectStatisticsStep implements Tasklet {
    private static final Logger logger = LoggerFactory.getLogger(CollectStatisticsStep.class);

    @Autowired
    private ProductRepository productRepository;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) {
        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);
        UUID sbomId = jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start CollectStatisticsStep sbomId:{}", sbomId);

        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));
        Sbom sbom = product.getSbom();

        ProductStatistics statistics = new ProductStatistics();
        statistics.setProduct(product);
        statistics.setCreateTime(new Timestamp(ExecutionContextUtils.getJobExecution(contribution).getCreateTime().getTime()));
        collectDepStatistics(statistics, sbom);
        collectVulStatistics(statistics, sbom);
        collectLicenseStatistics(statistics, sbom);
        product.addProductStatistics(statistics);

        collectPackageStatistics(sbom);
        productRepository.save(product);

        logger.info("finish CollectStatisticsStep sbomId:{}", sbomId);
        return RepeatStatus.FINISHED;
    }

    private void collectDepStatistics(ProductStatistics statistics, Sbom sbom) {
        Map<String, Long> categoryPackageCountMap = sbom.getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .collect(Collectors.groupingBy(ExternalPurlRef::getCategory, Collectors.counting()));

        statistics.setPackageCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.PACKAGE_MANAGER.name(), 0L));
        statistics.setDepCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.EXTERNAL_MANAGER.name(), 0L));
        statistics.setModuleCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.PROVIDE_MANAGER.name(), 0L));
        statistics.setRuntimeDepCount(sbom.getPackages().stream()
                .map(pkg -> getPackageRuntimeDepSpdxIdList(pkg, sbom))
                .flatMap(List::stream)
                .distinct()
                .count());
    }

    private void collectVulStatistics(ProductStatistics statistics, Sbom sbom) {
        statistics.setVulCount(sbom.getPackages().stream()
                .map(Package::getExternalVulRefs)
                .flatMap(List::stream)
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .count());

        Map<CvssSeverity, Long> vulSeverityVulCountMap = sbom.getPackages().stream()
                .map(Package::getExternalVulRefs)
                .flatMap(List::stream)
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .collect(Collectors.groupingBy(CvssSeverity::calculateVulCvssSeverity, Collectors.counting()));
        statistics.setCriticalVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.CRITICAL, 0L));
        statistics.setHighVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.HIGH, 0L));
        statistics.setMediumVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.MEDIUM, 0L));
        statistics.setLowVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.LOW, 0L));
        statistics.setNoneVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.NONE, 0L));
        statistics.setUnknownVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.UNKNOWN, 0L));

        Map<CvssSeverity, Long> vulSeverityPackageCountMap = sbom.getPackages().stream()
                .collect(Collectors.groupingBy(pkg -> calculatePackageMostSevereCvssSeverity(pkg.getExternalVulRefs()), Collectors.counting()));
        statistics.setPackageWithCriticalVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.CRITICAL, 0L));
        statistics.setPackageWithHighVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.HIGH, 0L));
        statistics.setPackageWithMediumVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.MEDIUM, 0L));
        statistics.setPackageWithLowVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.LOW, 0L));
        statistics.setPackageWithNoneVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.NONE, 0L));
        statistics.setPackageWithUnknownVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.UNKNOWN, 0L));
        statistics.setPackageWithoutVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.NA, 0L));
    }

    private CvssSeverity calculatePackageMostSevereCvssSeverity(List<ExternalVulRef> externalVulRefs) {
        if (ObjectUtils.isEmpty(externalVulRefs)) {
            return CvssSeverity.NA;
        }
        return externalVulRefs.stream()
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .map(CvssSeverity::calculateVulCvssSeverity)
                .max((Comparator.comparing(CvssSeverity::getSeverity)))
                .orElse(CvssSeverity.UNKNOWN);
    }

    private void collectLicenseStatistics(ProductStatistics statistics, Sbom sbom) {
        statistics.setLicenseCount(sbom.getPackages().stream()
                .map(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).collect(Collectors.toSet()))
                .flatMap(Set::stream)
                .distinct()
                .count());
        statistics.setPackageWithMultiLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).count() > 1)
                .count());
        statistics.setPackageWithoutLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).findAny().isEmpty())
                .count());
        statistics.setPackageWithLegalLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).findAny().isPresent())
                .filter(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).allMatch(License::getIsLegal))
                .count());
        statistics.setPackageWithIllegalLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).anyMatch(license -> !license.getIsLegal()))
                .count());

        TreeMap<String, Long> licenseDistribution = new TreeMap<>();
        sbom.getPackages().stream()
                .map(pkg -> pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).collect(Collectors.toSet()))
                .forEach(licenses -> licenses.forEach(license -> licenseDistribution.merge(license.getSpdxLicenseId(), 1L, Long::sum)));

        statistics.setLicenseDistribution(licenseDistribution);
    }

    private void collectPackageStatistics(Sbom sbom) {
        sbom.getPackages().forEach(pkg -> {
            PackageStatistics statistics = new PackageStatistics();
            collectPackageDepStatistics(statistics, pkg);
            collectPackageVulStatistics(statistics, pkg);
            collectPackageLicenseStatistics(statistics, pkg);
            statistics.setPkg(pkg);
            pkg.setPackageStatistics(statistics);
        });
    }

    private void collectPackageDepStatistics(PackageStatistics statistics, Package pkg) {
        Map<String, Long> categoryPackageCountMap = pkg.getExternalPurlRefs().stream()
                .collect(Collectors.groupingBy(ExternalPurlRef::getCategory, Collectors.counting()));

        statistics.setDepCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.EXTERNAL_MANAGER.name(), 0L));
        statistics.setModuleCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.PROVIDE_MANAGER.name(), 0L));
        statistics.setRuntimeDepCount((long) getPackageRuntimeDepSpdxIdList(pkg, pkg.getSbom()).size());
    }

    private List<String> getPackageRuntimeDepSpdxIdList(Package pkg, Sbom sbom) {
        return sbom.getSbomElementRelationships().stream()
                .filter(it -> StringUtils.equals(it.getElementId(), pkg.getSpdxId()))
                .map(SbomElementRelationship::getRelatedElementId)
                .toList();
    }

    private void collectPackageVulStatistics(PackageStatistics statistics, Package pkg) {
        statistics.setVulCount(pkg.getExternalVulRefs().stream()
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .count());

        Map<CvssSeverity, Long> vulSeverityVulCountMap = pkg.getExternalVulRefs().stream()
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .collect(Collectors.groupingBy(CvssSeverity::calculateVulCvssSeverity, Collectors.counting()));
        statistics.setCriticalVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.CRITICAL, 0L));
        statistics.setHighVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.HIGH, 0L));
        statistics.setMediumVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.MEDIUM, 0L));
        statistics.setLowVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.LOW, 0L));
        statistics.setNoneVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.NONE, 0L));
        statistics.setUnknownVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.UNKNOWN, 0L));

        statistics.setSeverity(calculatePackageMostSevereCvssSeverity(pkg.getExternalVulRefs()).name());
    }

    private void collectPackageLicenseStatistics(PackageStatistics statistics, Package pkg) {
        statistics.setLicenseCount((long) pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).collect(Collectors.toSet()).size());
        statistics.setLicenses(pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).map(License::getSpdxLicenseId).toList());
        statistics.setLegalLicense(pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).findAny().isPresent() ?
                pkg.getPkgLicenseRelps().stream().map(PkgLicenseRelp::getLicense).allMatch(License::getIsLegal) : null);
    }
}
