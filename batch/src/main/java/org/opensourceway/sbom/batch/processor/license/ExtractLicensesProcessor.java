package org.opensourceway.sbom.batch.processor.license;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.api.license.LicenseService;
import org.opensourceway.sbom.cache.LicenseObjectCache;
import org.opensourceway.sbom.cache.LicenseStandardMapCache;
import org.opensourceway.sbom.cache.RepoMetaLicenseCache;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.License;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgLicenseRelp;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.vo.license.ExtractLicenseVo;
import org.opensourceway.sbom.model.pojo.vo.license.LicenseInfoVo;
import org.opensourceway.sbom.utils.RepoMetaUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public class ExtractLicensesProcessor implements ItemProcessor<List<ExternalPurlRef>, ExtractLicenseVo>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractLicensesProcessor.class);
    @Autowired
    private LicenseService licenseService;
    @Autowired
    private LicenseClient licenseClient;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private LicenseStandardMapCache licenseStandardMapCache;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private RepoMetaLicenseCache repoMetaLicenseCache;

    @Autowired
    private RepoMetaUtil repoMetaUtil;

    @Autowired
    private LicenseObjectCache licenseObjectCache;

    @Value("${isScan}")
    private Boolean isScan;

    @Nullable
    @Override
    public ExtractLicenseVo process(List<ExternalPurlRef> chunk) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseProcessor sbomId:{}, chunk size:{}, first item id:{}",
                sbomId,
                chunk.size(),
                CollectionUtils.isEmpty(chunk) ? "" : chunk.get(0).getId().toString());

        ExtractLicenseVo vo = extractLicenseForPurlRefChunk(sbomId, chunk);

        logger.info("finish ExtractLicenseProcessor sbomId: {}, pkg size: {}, license size: {}, relp size: {}",
                sbomId, vo.getPackages().size(), vo.getLicenses().size(), vo.getLicenseOfRelp().size());
        return vo;
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

    private ExtractLicenseVo extractLicenseForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk) {
        logger.info("Start to extract License for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, LicenseInfoVo>> resultSet;
        Product product = productRepository.findBySbomId(sbomId);
        if (SbomConstants.PRODUCT_OPENEULER_NAME.equals(product.getProductType())) {
            resultSet = extractLicenseWithRepoMeta(sbomId, externalPurlChunk, product);
        } else {
            resultSet = extractLicenseWithoutRepoMeta(sbomId, externalPurlChunk, product);
        }
        logger.info("End to extract license for sbom {}", sbomId);
        return getLicenseAndPkgToDeal(resultSet);
    }

    private Set<Pair<ExternalPurlRef, LicenseInfoVo>> extractLicenseWithRepoMeta(UUID sbomId, List<ExternalPurlRef> externalPurlChunk, Product product) {
        Set<Pair<ExternalPurlRef, LicenseInfoVo>> resultSet = new HashSet<>();
        List<String> noRepoMetaPkgList = new ArrayList<>();
        for (ExternalPurlRef purlRef : externalPurlChunk) {
            RepoMeta repoMeta = repoMetaUtil.getRepoMeta(product, purlRef.getPurl().getName()).orElse(null);
            if (ObjectUtils.isEmpty(repoMeta)) {
                noRepoMetaPkgList.add(purlRef.getPurl().getName());
            } else {
                RepoMeta openEulerRepoMeta = repoMetaLicenseCache.getRepoMeta(purlRef.getPurl(), product, repoMeta.getRepoName(), repoMeta.getBranch());
                if (openEulerRepoMeta.getExtendedAttr().get(SbomRepoConstants.REPO_LICENSE) == null) {
                    continue;
                }
                LicenseInfoVo licenseInfoVo = new LicenseInfoVo((List<String>) openEulerRepoMeta.getExtendedAttr().get(SbomRepoConstants.REPO_LICENSE),
                        (List<String>) openEulerRepoMeta.getExtendedAttr().get(SbomRepoConstants.REPO_LICENSE_LEGAL),
                        (List<String>) openEulerRepoMeta.getExtendedAttr().get(SbomRepoConstants.REPO_LICENSE_ILLEGAL),
                        (List<String>) openEulerRepoMeta.getExtendedAttr().get(SbomRepoConstants.REPO_COPYRIGHT));
                resultSet.add(Pair.of(purlRef, licenseInfoVo));
            }
        }
        if (!ObjectUtils.isEmpty(noRepoMetaPkgList)) {
            logger.warn("ExtractLicenseProcessor can't find package's repoMeta, sbomId:{}, branch:{}, pkgName list:{}",
                    sbomId,
                    product.getProductVersion(),
                    noRepoMetaPkgList);
        }

        return resultSet;
    }

    private Set<Pair<ExternalPurlRef, LicenseInfoVo>> extractLicenseWithoutRepoMeta(UUID sbomId, List<ExternalPurlRef> externalPurlChunk, Product product) {
        Set<Pair<ExternalPurlRef, LicenseInfoVo>> resultSet = new HashSet<>();
        Set<String> repoPurlSet = new HashSet<>();
        Map<ExternalPurlRef, String> pkgRepoPurlTrans = new HashMap<>();
        externalPurlChunk.forEach(purlRef -> {
            String purlForLicense = licenseService.getPurlsForLicense(purlRef.getPurl(), product);
            if (!Objects.isNull(purlForLicense)) {
                repoPurlSet.add(purlForLicense);
                pkgRepoPurlTrans.put(purlRef, purlForLicense);
            }
        });

        try {
            Map<String, LicenseInfoVo> licenseInfoVoMap = licenseService.getLicenseInfoVoFromPurl(new ArrayList<>(repoPurlSet));
            for (ExternalPurlRef purlRef : externalPurlChunk) {
                resultSet.add(Pair.of(purlRef, licenseInfoVoMap.get(pkgRepoPurlTrans.get(purlRef))));
            }

        } catch (Exception e) {
            logger.error("failed to extract License for sbom {}", sbomId);
            throw new RuntimeException(e);
        }
        return resultSet;
    }

    private ExtractLicenseVo getLicenseAndPkgToDeal(Set<Pair<ExternalPurlRef, LicenseInfoVo>> externalLicenseRefSet) {
        Map<String, List<String>> chunkIllegalLicenseInfo = new HashMap<>();
        ExtractLicenseVo vo = new ExtractLicenseVo();
        for (Pair<ExternalPurlRef, LicenseInfoVo> externalLicenseRefPair : externalLicenseRefSet) {
            ExternalPurlRef purlRef = externalLicenseRefPair.getLeft();
            LicenseInfoVo licenseInfoVo = externalLicenseRefPair.getRight();
            if (ObjectUtils.isEmpty(licenseInfoVo)) {
                continue;
            }
            Package pkg = packageRepository.findById(purlRef.getPkg().getId()).orElseThrow();
            if (!ObjectUtils.isEmpty(licenseInfoVo.getRepoLicenseIllegal())) {
                chunkIllegalLicenseInfo.put(pkg.getName(), licenseInfoVo.getRepoLicenseIllegal());
            }
            setLicenseAndCopyrightForPackage(licenseInfoVo, pkg);
            setLicenseAndPkgInfo(vo, licenseInfoVo, pkg);
        }

        if (MapUtils.isNotEmpty(chunkIllegalLicenseInfo)) {
            logger.warn("illegal licenses info in chunks:{}", chunkIllegalLicenseInfo);
        }
        return vo;
    }

    private void setLicenseAndPkgInfo(ExtractLicenseVo vo, LicenseInfoVo licenseInfoVo, Package pkg) {
        List<String> illegalLicenseList = licenseInfoVo.getRepoLicenseIllegal();
        List<String> licenseList = new ArrayList<>(illegalLicenseList);
        licenseList.addAll(licenseInfoVo.getRepoLicenseLegal());
        setLicenseAndCopyrightForPackage(licenseInfoVo, pkg);
        licenseList.stream()
                .map(lic -> licenseStandardMapCache.getLicenseStandardMap(CacheConstants.LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN).getOrDefault(lic.toLowerCase(), lic))
                .forEach(lic -> {
                    License license = licenseObjectCache.getLicenseCache(lic, getLicenseLegality(illegalLicenseList, lic));
                    if (pkg.getPkgLicenseRelps().stream().noneMatch(relp -> lic.equals(vo.getLicenseOfRelp().get(relp)))) {
                        PkgLicenseRelp pkgLicenseRelp = new PkgLicenseRelp();
                        pkgLicenseRelp.setPkg(pkg);
                        pkg.addPkgLicenseRelp(pkgLicenseRelp);
                        vo.putPkgLicenseRelp(pkgLicenseRelp, lic);
                    }
                    vo.addPackage(pkg);
                    vo.addLicense(license);
                });
    }


    private Boolean getLicenseLegality(List<String> illegalLicenseList, String lic) {

        return !illegalLicenseList.contains(lic);
    }

    private void setLicenseAndCopyrightForPackage(LicenseInfoVo licenseInfoVo, Package pkg) {
        if (licenseInfoVo.getRepoCopyrightLegal().size() != 0) {
            pkg.setCopyright(licenseInfoVo.getRepoCopyrightLegal().get(0));
        }
        if (licenseInfoVo.getRepoLicense().size() != 0) {
            pkg.setLicenseConcluded(licenseInfoVo.getRepoLicense().get(0));
        }
    }

}