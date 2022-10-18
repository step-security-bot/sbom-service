package org.opensourceway.sbom.manager.service.license.impl;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.cache.constant.CacheConstants;
import org.opensourceway.sbom.clients.license.LicenseClient;
import org.opensourceway.sbom.clients.license.vo.ComplianceResponse;
import org.opensourceway.sbom.clients.license.vo.LicenseNameAndUrl;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.LicenseRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.service.license.LicenseService;
import org.opensourceway.sbom.manager.utils.cache.LicenseInfoMapCache;
import org.opensourceway.sbom.openeuler.obs.SbomRepoConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Service
@Qualifier("LicenseServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class LicenseServiceImpl implements LicenseService {
    private static final Logger logger = LoggerFactory.getLogger(LicenseServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 128;

    @Autowired
    private LicenseClient licenseClient;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private LicenseInfoMapCache licenseInfoMapCache;

    @Value("${isScan}")
    private Boolean isScan;


    private void scanLicense(ComplianceResponse element) {
        try {
            licenseClient.scanLicenseFromPurl(element.getPurl());
        } catch (Exception e) {
            logger.error("failed to scan license for purl {}", element.getPurl());
            throw e;
        }
    }

    private Boolean isContainPackage(Package pkg, License license) {
        for (Package pkgs : license.getPackages()) {
            if (pkgs.getId().equals(pkg.getId())) {
                return true;
            }
        }
        return false;
    }


    public String getPurlsForLicense(PackageUrlVo packageUrlVo, Product product) {
        String purl = "";
        String productType = String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_TYPE_KEY));
        try {

            if (SbomConstants.PRODUCT_MINDSPORE_NAME.equals(productType)) {
                purl = dealMindsporePurl(packageUrlVo);
            } else if (SbomConstants.PRODUCT_OPENEULER_NAME.equals(productType)) {
                purl = dealOpenEulerPurl(packageUrlVo, product);
            }
        } catch (MalformedPackageURLException e) {
            logger.error("failed to get purl for License ");
            return null;
        }
        return purl;
    }

    /***
     * change openEuler purl format to get license
     * for example:
     * pkg:rpm/nodejs-lodash-some@3.10.1-1.oe2203 -> pkg:gitee/src-openeuler/nodejs-lodash-some@openEuler-22.03-LTS
     ***/
    private String dealOpenEulerPurl(PackageUrlVo packageUrlVo, Product product) throws MalformedPackageURLException {
        if (!"rpm".equals(packageUrlVo.getType())) {

            return (new PackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(), packageUrlVo.getName(),
                    packageUrlVo.getVersion(), null, null)).canonicalize();
        } else {
            return (new PackageURL("gitee", SbomRepoConstants.OPENEULER_REPO_ORG, packageUrlVo.getName(),
                    (String) product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY),
                    null, null)).canonicalize();

        }
    }

    /***
     * change MindSpore purl format to get license
     * for example:
     * pkg:gitee/mindspore/akg@1.7.0 -> pkg:gitee/mindspore/akg@v1.7.0
     ***/
    private String dealMindsporePurl(PackageUrlVo packageUrlVo) throws MalformedPackageURLException {
        if ("mindspore".equals(packageUrlVo.getNamespace())) {
            return (new PackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(), packageUrlVo.getName(),
                    "v" + packageUrlVo.getVersion(), null, null)).canonicalize();
        } else if (packageUrlVo.getType() != null && packageUrlVo.getType().contains("git")) {
            return (new PackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(), packageUrlVo.getName(),
                    packageUrlVo.getVersion(), null, null)).canonicalize();
        } else {
            return null;
        }
    }

    @Override
    public Integer getBulkRequestSize() {
        return BULK_REQUEST_SIZE;
    }

    @Override
    public boolean needRequest() {
        return licenseClient.needRequest();
    }

    @Override
    public Set<Pair<ExternalPurlRef, Object>> extractLicenseForPurlRefChunk(UUID sbomId,
                                                                            List<ExternalPurlRef> externalPurlChunk) {
        logger.info("Start to extract License for sbom {}, chunk size:{}", sbomId,
                externalPurlChunk.size());
        Set<Pair<ExternalPurlRef, Object>> resultSet = new HashSet<>();
        Product product = productRepository.findBySbomId(sbomId);

        try {
            List<String> purls = new ArrayList<>();
            externalPurlChunk.forEach(purlRef -> {
                String purlForLicense = getPurlsForLicense(purlRef.getPurl(), product);
                if (!Objects.isNull(purlForLicense)) {
                    purls.add(purlForLicense);
                }
            });
            ComplianceResponse[] responseArr = licenseClient.getComplianceResponse(purls);
            if (Objects.isNull(responseArr) || responseArr.length == 0) {
                return resultSet;
            }
            externalPurlChunk.forEach(ref ->
                    Arrays.stream(responseArr)
                            .filter(response -> StringUtils.equals(getPurlsForLicense(ref.getPurl(), product), response.getPurl()))
                            .forEach(licenseObj -> resultSet.add(Pair.of(ref, licenseObj))));

        } catch (Exception e) {
            logger.error("failed to extract License for sbom {}", sbomId);
            throw new RuntimeException(e);
        }
        logger.info("End to extract license for sbom {}", sbomId);
        return resultSet;
    }

    @Override
    public void persistExternalLicenseRefChunk(Set<Pair<ExternalPurlRef, Object>> externalLicenseRefSet) {
        int numOfNotScan = 0;
        for (Pair<ExternalPurlRef, Object> externalLicenseRefPair : externalLicenseRefSet) {
            ExternalPurlRef purlRef = externalLicenseRefPair.getLeft();
            ComplianceResponse response = (ComplianceResponse) externalLicenseRefPair.getRight();
            if (response.getResult().getIsSca().equals("true")) {
                List<String> illegalLicenseList = response.getResult().getRepoLicenseIllegal();
                List<String> licenseList = new ArrayList<>(illegalLicenseList);
                licenseList.addAll(response.getResult().getRepoLicenseLegal());
                Package pkg = packageRepository.findById(purlRef.getPkg().getId()).orElseThrow();
                saveLicenseAndCopyrightForPackage(response, pkg);
                licenseList.forEach(lic -> {
                    License license = licenseRepository.findBySpdxLicenseId(lic).orElse(generateNewLicense(lic));
                    if (pkg.getLicenses() == null) {
                        pkg.setLicenses(new HashSet<>());
                    }
                    if (license.getPackages() == null) {
                        license.setPackages(new HashSet<>());
                    } else if (!isContainPackage(pkg, license)) {
                        pkg.getLicenses().add(license);
                        license.getPackages().add(pkg);
                    }
                    if (illegalLicenseList.contains(lic)) {
                        license.setIsLegal(false);
                        logger.error("license {} for {} is not legal", lic, purlRef.getPkg().getName());
                    } else {
                        license.setIsLegal(true);
                    }
                    licenseRepository.save(license);
                });
            } else {
                if (Boolean.TRUE.equals(isScan) && response.getPurl().startsWith("pkg:git")) {
                    scanLicense(response);
                    numOfNotScan++;
                }
            }
        }
        logger.info("The num of package not scanned license: {}", numOfNotScan);
    }

    private void saveLicenseAndCopyrightForPackage(ComplianceResponse response, Package pkg) {
        if (response.getResult().getRepoCopyrightLegal().size() != 0) {
            pkg.setCopyright(response.getResult().getRepoCopyrightLegal().get(0));
        }
        if (response.getResult().getRepoLicense().size() != 0) {
            pkg.setLicenseConcluded(response.getResult().getRepoLicense().get(0));
        }
        packageRepository.save(pkg);
    }

    private License generateNewLicense(String lic) {
        License license = new License();
        license.setSpdxLicenseId(lic);

        // use cache
        Map<String, LicenseNameAndUrl> licenseInfoMap = licenseInfoMapCache.getLicenseInfoMap(CacheConstants.LICENSE_INFO_MAP_CACHE_KEY_DEFAULT_VALUE);
        if (licenseInfoMap != null && licenseInfoMap.containsKey(lic)) {
            LicenseNameAndUrl licenseInfo = licenseInfoMap.get(lic);
            license.setName(licenseInfo.getName());
            license.setUrl(licenseInfo.getUrl());
        }
        return license;
    }
}
