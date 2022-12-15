package org.opensourceway.sbom.manager.batch.processor.license;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.clients.license.LicenseClient;
import org.opensourceway.sbom.clients.license.vo.ComplianceResponse;
import org.opensourceway.sbom.clients.license.vo.LicenseInfo;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.batch.pojo.LicenseInfoVo;
import org.opensourceway.sbom.manager.dao.LicenseRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.PkgLicenseRelp;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.opensourceway.sbom.manager.service.license.LicenseService;
import org.opensourceway.sbom.manager.utils.cache.LicenseInfoMapCache;
import org.opensourceway.sbom.manager.utils.cache.LicenseStandardMapCache;
import org.opensourceway.sbom.manager.utils.cache.OpenEulerRepoMetaCache;
import org.opensourceway.sbom.openeuler.obs.SbomRepoConstants;
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

public class ExtractLicensesProcessor implements ItemProcessor<List<ExternalPurlRef>, List<Pair<Package, License>>>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(ExtractLicensesProcessor.class);
    @Autowired
    private LicenseService licenseService;
    @Autowired
    private LicenseClient licenseClient;
    private StepExecution stepExecution;
    private ExecutionContext jobContext;

    @Autowired
    private LicenseInfoMapCache licenseInfoMapCache;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private LicenseStandardMapCache licenseStandardMapCache;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private OpenEulerRepoMetaCache openEulerRepoMetaCache;

    @Value("${isScan}")
    private Boolean isScan;

    @Nullable
    @Override
    public List<Pair<Package, License>> process(List<ExternalPurlRef> chunk) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        logger.info("start ExtractLicenseProcessor sbomId:{}, chunk size:{}, first item id:{}",
                sbomId,
                chunk.size(),
                CollectionUtils.isEmpty(chunk) ? "" : chunk.get(0).getId().toString());

        List<Pair<Package, License>> resultSet = extractLicenseForPurlRefChunk(
                sbomId, chunk, (Map<String, License>) stepExecution.getExecutionContext().get(BatchContextConstants.BATCH_STEP_LICENSE_MAP_KEY));

        logger.info("finish ExtractLicenseProcessor sbomId:{}, resultSet size:{}", sbomId, resultSet.size());
        return resultSet;
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

    private List<Pair<Package, License>> extractLicenseForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk, Map<String, License> spdxLicenseIdMap) {
        logger.info("Start to extract License for sbom {}, chunk size:{}", sbomId, externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, LicenseInfoVo>> resultSet = new HashSet<>();
        Product product = productRepository.findBySbomId(sbomId);
        String productVersion = String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY));
        String productType = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY);
        List<String> noRepoMetaPkgList = new ArrayList<>();

        Set<String> repoPurlSet = new HashSet<>();
        Map<String, String> pkgRepoPurlTrans = new HashMap<>();
        if (SbomConstants.PRODUCT_OPENEULER_NAME.equals(productType)) {
            resultSet = extractOpenEulerLicense(sbomId, externalPurlChunk, productType, productVersion);
        } else {
            resultSet = extractOtherLicense(externalPurlChunk, product);
        }
        if (!org.springframework.util.ObjectUtils.isEmpty(noRepoMetaPkgList)) {
            logger.warn("ExtractLicenseProcessor can't find package's repoMeta, sbomId:{}, branch:{}, pkgName list:{}",
                    sbomId,
                    productVersion,
                    noRepoMetaPkgList);
        }

        logger.info("End to extract license for sbom {}", sbomId);
        return getLicenseAndPkgToDeal(resultSet, spdxLicenseIdMap);
    }

    private Set<Pair<ExternalPurlRef, LicenseInfoVo>> extractOpenEulerLicense(UUID sbomId, List<ExternalPurlRef> externalPurlChunk, String productType, String productVersion) {
        Set<Pair<ExternalPurlRef, LicenseInfoVo>> resultSet = new HashSet<>();
        List<String> noRepoMetaPkgList = new ArrayList<>();
        for (ExternalPurlRef purlRef : externalPurlChunk) {
            List<RepoMeta> repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(productType, productVersion, purlRef.getPurl().getName());
            if (ObjectUtils.isEmpty(repoMetaList)) {
                noRepoMetaPkgList.add(purlRef.getPurl().getName());
            } else {
                RepoMeta repoMeta = repoMetaList.get(0);
                RepoMeta openEulerRepoMeta = openEulerRepoMetaCache.getRepoMeta(repoMeta.getRepoName(), repoMeta.getBranch());
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
        if (!org.springframework.util.ObjectUtils.isEmpty(noRepoMetaPkgList)) {
            logger.warn("ExtractLicenseProcessor can't find package's repoMeta, sbomId:{}, branch:{}, pkgName list:{}",
                    sbomId,
                    productVersion,
                    noRepoMetaPkgList);
        }

        return resultSet;
    }

    private Set<Pair<ExternalPurlRef, LicenseInfoVo>> extractOtherLicense(List<ExternalPurlRef> externalPurlChunk, Product product) {
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
            Map<String, LicenseInfoVo> licenseInfoVoMap = licenseService.getLicenseInfoVoFromPurl(repoPurlSet.stream().toList());
            for (ExternalPurlRef purlRef : externalPurlChunk) {
                resultSet.add(Pair.of(purlRef, licenseInfoVoMap.get(pkgRepoPurlTrans.get(purlRef))));
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return resultSet;
    }

    private List<Pair<Package, License>> getLicenseAndPkgToDeal(Set<Pair<ExternalPurlRef, LicenseInfoVo>> externalLicenseRefSet, Map<String, License> spdxLicenseIdMap) {
        Map<String, List<String>> illegalLicenseInfo = new HashMap<>();
        List<Pair<Package, License>> dataToSave = new ArrayList<>();
        int numOfNotScan = 0;
        for (Pair<ExternalPurlRef, LicenseInfoVo> externalLicenseRefPair : externalLicenseRefSet) {
            ExternalPurlRef purlRef = externalLicenseRefPair.getLeft();
            LicenseInfoVo licenseVo = externalLicenseRefPair.getRight();
//            if (response.getResult().getIsSca().equals("true")) {
//            Map<String,List<String>> LicenseInfo= (Map<String, List<String>>) repoMeta.getExtendedAttr().get(SbomRepoConstants.LICENSE_INFO_KEY);
            if (ObjectUtils.isEmpty(licenseVo)) {
                continue;
            }
            List<String> illegalLicenseList = licenseVo.getRepoLicenseIllegal();
            List<String> legalLicenseList = licenseVo.getRepoLicenseLegal();
            Package pkg = packageRepository.findById(purlRef.getPkg().getId()).orElseThrow();
            setLicenseAndCopyrightForPackage(licenseVo, pkg);
            setLicenseAndPkgInfo(illegalLicenseInfo, dataToSave, purlRef, pkg, spdxLicenseIdMap, illegalLicenseList, legalLicenseList);
//            } else {
//                if (Boolean.TRUE.equals(isScan) && response.getPurl().startsWith("pkg:git")) {
//                    scanLicense(response);
//                    numOfNotScan++;
//                }
//            }
        }
//        logger.info("The num of package not scanned license: {}", numOfNotScan);
        Map<String, List<String>> chunkIllegalLicenseInfo = new HashMap<>();
        illegalLicenseInfo.forEach((pkgName, licList) -> {
            List<String> templist = chunkIllegalLicenseInfo.getOrDefault(pkgName, new ArrayList<>());
            templist.addAll(licList);
            chunkIllegalLicenseInfo.put(pkgName, templist);
        });
        if (MapUtils.isNotEmpty(chunkIllegalLicenseInfo)) {
            logger.warn("illegal licenses info in chunks:{}", illegalLicenseInfo);
        }
        return dataToSave;
    }


    private void setLicenseAndPkgInfo(Map<String, List<String>> illegalLicenseInfo, List<Pair<Package, License>> dataToSave, ExternalPurlRef purlRef, Package pkg, Map<String, License> spdxLicenseIdMap, List<String> illegalLicenseList, List<String> legalLicenseList) {
        List<String> licenseList = new ArrayList<>(illegalLicenseList);
        licenseList.addAll(legalLicenseList);
//        Package pkg = packageRepository.findById(purlRef.getPkg().getId()).orElseThrow();
//        setLicenseAndCopyrightForPackage(response, pkg);
        licenseList.forEach(lic -> {
            lic = licenseStandardMapCache.getLicenseStandardMap(CacheConstants.LICENSE_STANDARD_MAP_CACHE_KEY_PATTERN).getOrDefault(lic.toLowerCase(), lic);
            License license;
            license = getLicenseToDeal(spdxLicenseIdMap, lic);
            setLegalOrNot(illegalLicenseInfo, purlRef, illegalLicenseList, lic, license);
            if (!pkg.containLicense(license)) {
                PkgLicenseRelp pkgLicenseRelp = new PkgLicenseRelp();
                pkgLicenseRelp.setPkg(pkg);
                pkgLicenseRelp.setLicense(license);
                pkg.addPkgLicenseRelp(pkgLicenseRelp);
                license.addPkgLicenseRelp(pkgLicenseRelp);
            }
            dataToSave.add(Pair.of(pkg, license));
        });
    }

    private License getLicenseToDeal(Map<String, License> spdxLicenseIdMap, String lic) {
        License license;
        if (spdxLicenseIdMap.containsKey(lic)) {
            license = spdxLicenseIdMap.get(lic);
        } else {
            license = licenseRepository.findBySpdxLicenseId(lic).orElse(generateNewLicense(lic));
            spdxLicenseIdMap.put(lic, license);
        }
        return license;
    }

    private void setLegalOrNot(Map<String, List<String>> illegalLicenseInfo, ExternalPurlRef purlRef, List<String> illegalLicenseList, String lic, License license) {
        if (illegalLicenseList.contains(lic)) {
            license.setIsLegal(false);
            List<String> licList = illegalLicenseInfo.getOrDefault(purlRef.getPkg().getName(), new ArrayList<>());
            licList.add(lic);
            illegalLicenseInfo.put(purlRef.getPkg().getName(), licList);
        } else {
            license.setIsLegal(true);
        }
    }

    private void setLicenseAndCopyrightForPackage(LicenseInfoVo licenseVo, Package pkg) {
        if (licenseVo.getRepoCopyrightLegal().size() != 0) {
            pkg.setCopyright(licenseVo.getRepoCopyrightLegal().get(0));
        }
        if (licenseVo.getRepoLicense().size() != 0) {
            pkg.setLicenseConcluded(licenseVo.getRepoLicense().get(0));
        }
    }

    private void scanLicense(ComplianceResponse element) {
        try {
            licenseClient.scanLicenseFromPurl(element.getPurl());
        } catch (Exception e) {
            logger.error("failed to scan license for purl {}", element.getPurl());
        }
    }

    private License generateNewLicense(String lic) {
        License license = new License();
        license.setSpdxLicenseId(lic);

        // use cache
        Map<String, LicenseInfo> licenseInfoMap = licenseInfoMapCache.getLicenseInfoMap(CacheConstants.LICENSE_INFO_MAP_CACHE_KEY_DEFAULT_VALUE);
        if (MapUtils.isNotEmpty(licenseInfoMap) && licenseInfoMap.containsKey(lic)) {
            LicenseInfo licenseInfo = licenseInfoMap.get(lic);
            license.setName(licenseInfo.getName());
            license.setUrl(licenseInfo.getReference());
        }
        return license;
    }

}