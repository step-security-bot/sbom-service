package org.opensourceway.sbom.manager.batch.step;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.manager.batch.ExecutionContextUtils;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.ProductStatistics;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.VulScore;
import org.opensourceway.sbom.manager.model.VulScoringSystem;
import org.opensourceway.sbom.manager.model.Vulnerability;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.utils.CvssSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.Timestamp;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class CollectStatisticsStep implements Tasklet {
    private static final Logger logger = LoggerFactory.getLogger(CollectStatisticsStep.class);

    @Autowired
    private ProductRepository productRepository;

    @Override
    public RepeatStatus execute(@NotNull StepContribution contribution, @NotNull ChunkContext chunkContext) throws Exception {
        logger.info("start CollectStatisticsStep");

        ExecutionContext jobContext = ExecutionContextUtils.getJobContext(contribution);
        String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));
        Sbom sbom = product.getSbom();

        ProductStatistics statistics = new ProductStatistics();
        statistics.setProduct(product);
        statistics.setCreateTime(new Timestamp(ExecutionContextUtils.getJobExecution(contribution).getCreateTime().getTime()));
        collectPackageStatistics(statistics, sbom);
        collectVulStatistics(statistics, sbom);
        collectLicenseStatistics(statistics, sbom);

        product.addProductStatistics(statistics);
        productRepository.save(product);

        logger.info("finish CollectStatisticsStep");
        return RepeatStatus.FINISHED;
    }

    private void collectPackageStatistics(ProductStatistics statistics, Sbom sbom) {
        Map<String, Long> categoryPackageCountMap = sbom.getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .collect(Collectors.groupingBy(ExternalPurlRef::getCategory, Collectors.counting()));

        statistics.setPackageCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.PACKAGE_MANAGER.name(), 0L));
        statistics.setDepCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.EXTERNAL_MANAGER.name(), 0L));
        statistics.setModuleCount(categoryPackageCountMap.getOrDefault(ReferenceCategory.PROVIDE_MANAGER.name(), 0L));
        // TODO: no related data yet
        statistics.setRuntimeDepCount(0L);
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
                .collect(Collectors.groupingBy(vul -> calculateCvssSeverity(vul.getVulScores()), Collectors.counting()));
        statistics.setCriticalVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.CRITICAL, 0L));
        statistics.setHighVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.HIGH, 0L));
        statistics.setMediumVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.MEDIUM, 0L));
        statistics.setLowVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.LOW, 0L));
        statistics.setNoneVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.NONE, 0L));
        statistics.setUnknownVulCount(vulSeverityVulCountMap.getOrDefault(CvssSeverity.UNKNOWN, 0L));

        statistics.setPackageWithoutVulCount(sbom.getPackages().stream()
                .filter(ref -> ref.getExternalVulRefs().size() == 0)
                .count());
        Map<CvssSeverity, Long> vulSeverityPackageCountMap = sbom.getPackages().stream()
                .filter(ref -> ref.getExternalVulRefs().size() > 0)
                .collect(Collectors.groupingBy(pkg -> calculatePackageMostSevereCvssSeverity(pkg.getExternalVulRefs()), Collectors.counting()));
        statistics.setPackageWithCriticalVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.CRITICAL, 0L));
        statistics.setPackageWithHighVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.HIGH, 0L));
        statistics.setPackageWithMediumVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.MEDIUM, 0L));
        statistics.setPackageWithLowVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.LOW, 0L));
        statistics.setPackageWithNoneVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.NONE, 0L));
        statistics.setPackageWithUnknownVulCount(vulSeverityPackageCountMap.getOrDefault(CvssSeverity.UNKNOWN, 0L));
    }

    private CvssSeverity calculateCvssSeverity(List<VulScore> scores) {
        CvssSeverity cvssSeverity = CvssSeverity.UNKNOWN;

        if (scores.size() == 1) {
            cvssSeverity = CvssSeverity.calculateCvssSeverity(
                    VulScoringSystem.valueOf(scores.get(0).getScoringSystem()), scores.get(0).getScore());
        } else if (scores.size() > 1) {
            VulScore cvss3 = scores.stream()
                    .filter(score -> StringUtils.equals(score.getScoringSystem(), VulScoringSystem.CVSS3.name()))
                    .findFirst()
                    .orElse(null);
            VulScore cvss2 = scores.stream()
                    .filter(score -> StringUtils.equals(score.getScoringSystem(), VulScoringSystem.CVSS2.name()))
                    .findFirst()
                    .orElse(null);

            if (Objects.nonNull(cvss3)) {
                cvssSeverity = CvssSeverity.calculateCvssSeverity(VulScoringSystem.CVSS3, cvss3.getScore());
            } else if (Objects.nonNull(cvss2)) {
                cvssSeverity = CvssSeverity.calculateCvssSeverity(VulScoringSystem.CVSS2, cvss2.getScore());
            }
        }

        return cvssSeverity;
    }

    private CvssSeverity calculatePackageMostSevereCvssSeverity(List<ExternalVulRef> externalVulRefs) {
        return externalVulRefs.stream()
                .map(ExternalVulRef::getVulnerability)
                .distinct()
                .map(Vulnerability::getVulScores)
                .map(this::calculateCvssSeverity)
                .max((Comparator.comparing(CvssSeverity::getSeverity)))
                .orElse(CvssSeverity.UNKNOWN);
    }

    private void collectLicenseStatistics(ProductStatistics statistics, Sbom sbom) {
        statistics.setLicenseCount(sbom.getPackages().stream()
                .map(Package::getLicenses)
                .flatMap(Set::stream)
                .distinct()
                .count());
        statistics.setPackageWithMultiLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getLicenses().size() > 1)
                .count());
        statistics.setPackageWithoutLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getLicenses().size() == 0)
                .count());
        statistics.setPackageWithLegalLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getLicenses().stream().anyMatch(License::getIsLegal))
                .count());
        statistics.setPackageWithIllegalLicenseCount(sbom.getPackages().stream()
                .filter(pkg -> pkg.getLicenses().stream().anyMatch(license -> !license.getIsLegal()))
                .count());

        TreeMap<String, Long> licenseDistribution = new TreeMap<>();
        sbom.getPackages().stream()
                .map(Package::getLicenses)
                .forEach(licenses -> licenses.forEach(license -> licenseDistribution.merge(license.getSpdxLicenseId(), 1L, Long::sum)));

        statistics.setLicenseDistribution(licenseDistribution);
    }
}
