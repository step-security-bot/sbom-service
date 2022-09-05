package org.opensourceway.sbom.manager.service.license.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.clients.license.LicenseClient;
import org.opensourceway.sbom.clients.license.model.ComponentReport;
import org.opensourceway.sbom.clients.license.model.Detail;
import org.opensourceway.sbom.clients.license.model.LicenseInfo;
import org.opensourceway.sbom.manager.dao.LicenseRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.service.license.AbstractLicenseService;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

@Service
@Qualifier("LicenseServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class LicenseServiceImpl extends AbstractLicenseService {
    private static final Logger logger = LoggerFactory.getLogger(LicenseServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 64;

    @Autowired
    private LicenseClient licenseClient;

    @Autowired
    private LicenseRepository licenseRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private ProductRepository productRepository;

    public static Map<String, Map<String, String>> FormatLicenseInfos(LicenseInfo[] licenseInfos) {
        Map<String, Map<String, String>> licenseInfoMap = new HashMap<>();
        Arrays.stream(licenseInfos).forEach(licenseInfo -> {
            Map<String, String> tmpInfo = new HashMap<>();
            tmpInfo.put("name", licenseInfo.getName());
            if (licenseInfo.getText().size() == 0) {
                tmpInfo.put("url", null);
            } else {
                tmpInfo.put("url", licenseInfo.getText().get(0).getUrl());
            }

            licenseInfoMap.put(licenseInfo.getId(), tmpInfo);
        });
        return licenseInfoMap;
    }

    @Override
    public void persistLicenseForSbom(Sbom sbom, Boolean blocking) {
        logger.info("Start to persistLicenseRefForSbom for sbom {}", sbom.getId());
        if (!licenseClient.needRequest()) {
            logger.warn("LicenseClient does not request");
            return;
        }
        Product product = sbom.getProduct();


        List<ExternalPurlRef> externalPurlRefs =
                sbom.getPackages().stream().map(Package::getExternalPurlRefs).flatMap(List::stream).filter(externalPurlRef -> externalPurlRef.getCategory().equals("PACKAGE_MANAGER")).toList();

        List<List<ExternalPurlRef>> chunks = ListUtils.partition(externalPurlRefs, BULK_REQUEST_SIZE);
        Mono<LicenseInfo[]> licInfoMono;
        Map<String, Map<String, String>> licenseInfoMap;
        try {
            licInfoMono = licenseClient.getLicenseInfo();
            licenseInfoMap = FormatLicenseInfos(licInfoMono.block());
        } catch (Exception e) {
            logger.error("failed to fetch license info for sbom.");
            throw e;
        }
        for (int i = 0; i < chunks.size(); i++) {
            logger.info("fetch license for purl chunk {}, total {}", i + 1, chunks.size());
            List<ExternalPurlRef> chunk = chunks.get(i);
            List<String> purls = chunk.stream().map(ref -> PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize()).collect(Collectors.toSet()).stream().toList();
            List<String> purlsForLicense = new ArrayList<>();
            purls.forEach(purl -> purlsForLicense.add(getPurlsForLicense(purl, true, product)));
            try {
                Mono<ComponentReport[]> mono = licenseClient.getComponentReport(purlsForLicense);

                persistLicense(mono.block(), licenseInfoMap, chunk, product);

            } catch (Exception e) {
                logger.error("failed to fetch license for sbom {}", sbom.getId());
                throw e;
            }
        }

        logger.info("End to persistLicenseRefForSbom  for sbom {}", sbom.getId());
    }

    private void persistLicense(ComponentReport[] reports, Map<String, Map<String, String>> licenseInfoMap, List<ExternalPurlRef> externalPurlRefs, Product product) {
        if (Objects.isNull(reports) || reports.length == 0) {
            return;
        }

        externalPurlRefs.forEach(ref -> Arrays.stream(reports).filter(element -> StringUtils.equals(getPurlsForLicense(PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize(), false, product), element.getPurl())).forEach(element -> {
            if (element.getResult().getRepoLicenseLegal().getPass().equals("true")) {
                List<String> illegalLicenseList = getIllegalLicenseList(element.getResult().getRepoLicenseLegal().getIsLegal().getDetail());
                element.getResult().getRepoLicenseLegal().getIsLegal().getLicense().forEach(lic -> {
                    License license = licenseRepository.findByName(lic).orElse(new License());
                    license.setName(lic);
                    getLicenseIdAndUrl(license, licenseInfoMap, lic);
                    if (license.getPackages() == null) {
                        license.setPackages(new HashSet<>());
                    }
                    Package pkg = packageRepository.findById(ref.getPkg().getId()).orElseThrow();
                    if (pkg.getLicenses() == null) {
                        pkg.setLicenses(new HashSet<>());
                    }
                    if (!isContainLicense(pkg, license)) {
                        pkg.getLicenses().add(license);
                        license.getPackages().add(pkg);
                    }
                    if (illegalLicenseList.size() != 0 && illegalLicenseList.contains(lic)) {
                        license.setIsLegal(false);
                        logger.error("license {} for {} is not legal", lic, ref.getPkg().getName());
                    } else {
                        license.setIsLegal(true);
                    }
                    licenseRepository.save(license);
                });
            } else {
                if (element.getPurl().startsWith("pkg:gitee"))
                    scanLicense(element);
            }
        }));

    }

    private List<String> getIllegalLicenseList(Detail detail) {
        List<String> illegalLicenseList = new ArrayList<>();
        if (detail.getIsStandard().getPass().equals("false") && detail.getIsStandard().getRisks().size() != 0) {
            illegalLicenseList.addAll(detail.getIsStandard().getRisks());
        }
        if (detail.getIsWhite().getPass().equals("false") && detail.getIsWhite().getRisks().size() != 0) {
            illegalLicenseList.addAll(detail.getIsWhite().getRisks());
        }
        if (detail.getIsReview().getPass().equals("false") && detail.getIsReview().getRisks().size() != 0) {
            illegalLicenseList.addAll(detail.getIsReview().getRisks());
        }
        return illegalLicenseList;
    }

    private void scanLicense(ComponentReport element) {
        try {
            logger.info("scan license for purl:{}", element.getPurl());
            Mono<org.opensourceway.sbom.clients.license.model.License> mono = licenseClient.scanLicenseFromPurl(element.getPurl());
            mono.timeout(Duration.ofSeconds(1)).subscribe(null, throwable -> {
                if (!(throwable instanceof TimeoutException && throwable.getMessage().startsWith("Did not observe any item or terminal signal within 1000ms "))) {
                    logger.error("scanLicense error", throwable);
                }
            });
        } catch (Exception e) {
            logger.error("failed to scan license for purl {}", element.getPurl());
            throw e;
        }

    }

    private void getLicenseIdAndUrl(License license, Map<String, Map<String, String>> licenseInfoMap, String lic) {
        if (licenseInfoMap.get(lic) == null) {
            logger.info("can not get licenseId and url for {}", lic);
        } else {
            if (licenseInfoMap.get(lic).get("name") != null) {
                license.setSpdxLicenseId(licenseInfoMap.get(lic).get("name"));
            }
            if (licenseInfoMap.get(lic).get("url") != null) {
                license.setUrl(licenseInfoMap.get(lic).get("url"));
            } else {
                logger.info("can not url info for {}", lic);
            }
        }
    }


    private Boolean isContainLicense(Package pkg, License license) {
        for (Package pkgs : license.getPackages()) {
            if (pkgs.getName().equals(pkg.getName())) {
                return true;
            }
        }
        return false;
    }


    private String getPurlsForLicense(String purl, Boolean quotationMarks, Product product) {
        String productType = String.valueOf(product.getAttribute().get("productType"));
        if (productType.equals("MindSpore")) {
            purl = dealMindsporePurl(purl);
        } else if (productType.equals("openEuler")) {
            String productVersion = String.valueOf(product.getAttribute().get("version"));
            purl = dealOpenEulerPurl(purl, productVersion);
        }


        if (quotationMarks) {
            purl = ("\"" + purl + "\"");
        }
        return purl;
    }

    private String dealOpenEulerPurl(String purl, String productVersion) {
        if (!purl.startsWith("pkg:rpm")) {
            return purl;
        }
        String groupAndName = purl.split("@")[0].split("/", 2)[1];
        String version = "openEuler-" + productVersion;
        purl = "pkg:gitee/src-openeuler/" + groupAndName + "@" + version;
        return purl;
    }

    private String dealMindsporePurl(String purl) {
        if (purl.split("/")[1].equals("mindspore")) {
            purl = (purl.split("@")[0] + "@" + "v" + purl.split("@")[1]);
        }
        return purl;
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
        List<String> requestPurls = externalPurlChunk.stream()
                .map(ref -> PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize())
                .collect(Collectors.toSet())
                .stream().toList();

        ListUtils.partition(requestPurls, getBulkRequestSize()).forEach(requestPurlsChunk -> {
            try {

                List<String> purls = new ArrayList<>();
                requestPurlsChunk.forEach(purl -> purls.add(getPurlsForLicense(purl, true, product)));
                ComponentReport[] response = licenseClient.getComponentReport(purls).block();
                if (Objects.isNull(response) || response.length == 0) {
                    return;
                }
                externalPurlChunk.forEach(ref -> Arrays.stream(response).filter(element -> StringUtils
                                .equals(getPurlsForLicense(PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize(), false, product), element.getPurl()) &&
                                ref.getCategory().equals("PACKAGE_MANAGER"))
                        .forEach(element -> resultSet.add(Pair.of(ref, element))));
            } catch (Exception e) {
                logger.error("failed to extract License for sbom {}", sbomId);
                reportLicenseFetchFailure(sbomId);
                throw e;
            }
        });

        logger.info("End to extract vulnerability from cve-manager for sbom {}", sbomId);
        return resultSet;
    }

    @Override
    public void persistExternalLicenseRefChunk(Set<Pair<ExternalPurlRef, Object>> externalLicenseRefSet, Map<String,
            Map<String, String>> licenseInfoMap) {
        for (Pair<ExternalPurlRef, Object> externalLicenseRefPair : externalLicenseRefSet) {
            ExternalPurlRef purlRef = externalLicenseRefPair.getLeft();
            ComponentReport response = (ComponentReport) externalLicenseRefPair.getRight();
            if (response.getResult().getRepoLicenseLegal().getPass().equals("true")) {
                List<String> illegalLicenseList =
                        getIllegalLicenseList(response.getResult().getRepoLicenseLegal().getIsLegal().getDetail());
                response.getResult().getRepoLicenseLegal().getIsLegal().getLicense().forEach(lic -> {
                    License license = licenseRepository.findByName(lic).orElse(new License());
                    license.setName(lic);
                    getLicenseIdAndUrl(license, licenseInfoMap, lic);
                    if (license.getPackages() == null) {
                        license.setPackages(new HashSet<>());
                    }
                    Package pkg = packageRepository.findById(purlRef.getPkg().getId()).orElseThrow();
                    if (pkg.getLicenses() == null) {
                        pkg.setLicenses(new HashSet<>());
                    }
                    if (!isContainLicense(pkg, license)) {
                        pkg.getLicenses().add(license);
                        license.getPackages().add(pkg);
                    }
                    if (illegalLicenseList.size() != 0 && illegalLicenseList.contains(lic)) {
                        license.setIsLegal(false);
                        logger.error("license {} for {} is not legal", lic, purlRef.getPkg().getName());
                    } else {
                        license.setIsLegal(true);
                    }
                    licenseRepository.save(license);
                });
            } else {
                if (response.getPurl().startsWith("pkg:gitee"))
                    scanLicense(response);
            }


//            License license = licenseRepository.saveAndFlush(persistLicense(lic);
//            Map<Pair<UUID, String>, License> existLicense =
//                    Optional.ofNullable(purlRef.getPkg().getLicenses())
//                            .orElse(new ArrayList<>())
//                            .stream()
//                            .collect(Collectors.toMap(it ->
//                                            Pair.of(it.getVulnerability().getId(), PurlUtil.PackageUrlVoToPackageURL(it.getPurl()).canonicalize()),
//                                    Function.identity()));
//            ExternalVulRef externalVulRef = existExternalVulRefs.getOrDefault(Pair.of(vulnerability.getId(), vul.getPurl()), new ExternalVulRef());
//            externalVulRef.setCategory(ReferenceCategory.SECURITY.name());
//            externalVulRef.setType(ReferenceType.CVE.getType());
//            externalVulRef.setStatus(Optional.ofNullable(externalVulRef.getStatus()).orElse(VulStatus.AFFECTED.name()));
//            externalVulRef.setPurl(PurlUtil.strToPackageUrlVo(vul.getPurl()));
//            externalVulRef.setVulnerability(vulnerability);
//            externalVulRef.setPkg(purlRef.getPkg());
//            externalVulRefRepository.saveAndFlush(externalVulRef);
        }
    }
}
