package org.openeuler.sbom.manager.service.license.impl;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.openeuler.sbom.clients.license.LicenseClient;
import org.openeuler.sbom.clients.license.model.ComponentReport;
import org.openeuler.sbom.manager.dao.LicenseRepository;
import org.openeuler.sbom.manager.dao.PackageRepository;
import org.openeuler.sbom.manager.model.ExternalPurlRef;
import org.openeuler.sbom.manager.model.License;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.Sbom;
import org.openeuler.sbom.manager.service.license.LicenseService;
import org.openeuler.sbom.manager.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

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

    @Override
    public void persistLicenseForSbom(Sbom sbom, Boolean blocking) {
        logger.info("Start to persistLicenseRefForSbom for sbom {}", sbom.getId());
        if (!licenseClient.needRequest()) {
            logger.warn("LicenseClient does not request");
            return;
        }

        List<ExternalPurlRef> externalPurlRefs = sbom.getPackages().stream()
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .toList();

        List<List<ExternalPurlRef>> chunks = ListUtils.partition(externalPurlRefs, BULK_REQUEST_SIZE);
        for (int i = 0; i < chunks.size(); i++) {
            logger.info("fetch license for purl chunk {}, total {}", i + 1, chunks.size());
            List<ExternalPurlRef> chunk = chunks.get(i);
            List<String> purls = chunk.stream()
                    .map(ref -> PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize())
                    .collect(Collectors.toSet())
                    .stream().toList();
            List<String> purlsForLicense = new ArrayList<>();
            purls.forEach(purl -> purlsForLicense.add(getPurlsForLicense(purl, true)));
            try {
                Mono<ComponentReport[]> mono = licenseClient.getComponentReport(purlsForLicense);

                persistLicense(mono.block(), chunk);

            } catch (Exception e) {
                logger.error("failed to fetch license for sbom {}", sbom.getId());
                throw e;
            }
        }

        logger.info("End to persistLicenseRefForSbom  for sbom {}", sbom.getId());
    }


    private void persistLicense(ComponentReport[] reports, List<ExternalPurlRef> externalPurlRefs) {
        if (Objects.isNull(reports) || reports.length == 0) {
            return;
        }

        externalPurlRefs.forEach(ref -> Arrays.stream(reports)
                .filter(element -> StringUtils.equals(getPurlsForLicense(PurlUtil.PackageUrlVoToPackageURL(ref.getPurl()).canonicalize(), false), element.getPurl()))
                .forEach(element -> {
                    if (element.getResult().getRepoLicenseLegal().getIsLegal().getPass().equals("true")) {
                        element.getResult().getRepoLicenseLegal().getIsLegal().getLicense().forEach(lic -> {
                            License license = licenseRepository.findByName(lic);
                            if (license == null) {
                                license = new License();
                                license.setName(lic);
                            }
                            if (license.getPackages() == null) {
                                license.setPackages(new HashSet<Package>());
                            }
                            Package pkg = packageRepository.findById(ref.getPkg().getId()).orElseThrow();
                            if (pkg.getLicenses() == null) {
                                pkg.setLicenses(new HashSet<License>());
                            }
                            pkg.getLicenses().add(license);
                            license.getPackages().add(pkg);
                            licenseRepository.save(license);
                        });
                    }
                }));

    }


    private String getPurlsForLicense(String purl, Boolean quotationMarks) {
        if (purl.split("/")[1].equals("mindspore")) {
            purl = (purl.split("@")[0] + "@" + "v" + purl.split("@")[1]);
        }
        if (quotationMarks) {
            purl = ("\"" + purl + "\"");
        }
        return purl;
    }

}
