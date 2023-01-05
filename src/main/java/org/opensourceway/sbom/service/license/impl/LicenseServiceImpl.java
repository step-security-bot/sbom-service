package org.opensourceway.sbom.service.license.impl;

import com.github.packageurl.MalformedPackageURLException;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.api.license.LicenseClient;
import org.opensourceway.sbom.api.license.LicenseService;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.response.license.ComplianceResponse;
import org.opensourceway.sbom.model.pojo.vo.license.LicenseInfoVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.utils.PurlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@Qualifier("LicenseServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class LicenseServiceImpl implements LicenseService {
    private static final Logger logger = LoggerFactory.getLogger(LicenseServiceImpl.class);

    private static final Integer BULK_REQUEST_SIZE = 128;

    @Autowired
    private LicenseClient licenseClient;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Override
    public Integer getBulkRequestSize() {
        return BULK_REQUEST_SIZE;
    }

    @Override
    public boolean needRequest() {
        return licenseClient.needRequest();
    }

    @Override
    public Map<String, LicenseInfoVo> getLicenseInfoVoFromPurl(List<String> purls) throws Exception {
        Map<String, LicenseInfoVo> licenseInfoVoMap = new HashMap<>();
        ComplianceResponse[] responseArr = licenseClient.getComplianceResponse(purls);
        if (ObjectUtils.isEmpty(responseArr)) {
            return licenseInfoVoMap;
        }
        for (ComplianceResponse response : responseArr) {
            if ("false".equals(response.getResult().getIsSca())) {
                scanLicense(response.getPurl());
                continue;
            }
            LicenseInfoVo licenseInfoVo = new LicenseInfoVo();
            licenseInfoVo.setRepoLicense(response.getResult().getRepoLicense());
            licenseInfoVo.setRepoLicenseIllegal(response.getResult().getRepoLicenseIllegal());
            licenseInfoVo.setRepoLicenseLegal(response.getResult().getRepoLicenseLegal());
            licenseInfoVo.setRepoCopyrightLegal(response.getResult().getRepoCopyrightLegal());
            licenseInfoVoMap.put(response.getPurl(), licenseInfoVo);
        }

        return licenseInfoVoMap;
    }

    @Override
    public String getPurlsForLicense(PackageUrlVo packageUrlVo, Product product) {
        String purl = "";
        try {

            if (SbomConstants.PRODUCT_MINDSPORE_NAME.equals(product.getProductType())) {
                purl = dealMindsporePurl(packageUrlVo);
            } else if (SbomConstants.PRODUCT_OPENEULER_NAME.equals(product.getProductType())) {
                purl = dealOpenEulerPurl(packageUrlVo, product);
            } else if (SbomConstants.PRODUCT_OPENHARMONY_NAME.equals(product.getProductType())) {
                purl = dealOpenHarmonyPurl(packageUrlVo, product);
            }
        } catch (MalformedPackageURLException e) {
            logger.error("failed to get purl for License ");
            return null;
        }
        return purl;
    }

    private void scanLicense(String purl) {
        try {
            licenseClient.scanLicenseFromPurl(purl);
        } catch (Exception e) {
            logger.error("failed to scan license for purl {}", purl);
        }
    }

    /***
     * change openEuler purl format to get license
     * for example:
     * pkg:rpm/nodejs-lodash-some@3.10.1-1.oe2203 -> pkg:gitee/src-openeuler/nodejs-lodash-some@openEuler-22.03-LTS
     ***/
    private String dealOpenEulerPurl(PackageUrlVo packageUrlVo, Product product) throws MalformedPackageURLException {
        if (!"rpm".equals(packageUrlVo.getType())) {
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(),
                    packageUrlVo.getName(), packageUrlVo.getVersion(), null, null)));
        } else {
            List<RepoMeta> repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(SbomConstants.PRODUCT_OPENEULER_NAME,
                    product.getProductVersion(), packageUrlVo.getName());
            String repoName = packageUrlVo.getName();
            if (!CollectionUtils.isEmpty(repoMetaList) && !repoMetaList.get(0).getDownloadLocation().isEmpty()) {
                String downloadLocation = repoMetaList.get(0).getDownloadLocation();
                List<String> repoInfo = Arrays.stream(Arrays.stream(downloadLocation.split("/tree/")).toList().get(0).split("/")).toList();
                repoName = repoInfo.get(repoInfo.size() - 1);
            }
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL("gitee", SbomRepoConstants.OPENEULER_REPO_ORG,
                    repoName, product.getProductVersion(), null, null)));

        }
    }

    /***
     * change MindSpore purl format to get license
     * for example:
     * pkg:gitee/mindspore/akg@1.7.0 -> pkg:gitee/mindspore/akg@v1.7.0
     ***/
    private String dealMindsporePurl(PackageUrlVo packageUrlVo) throws MalformedPackageURLException {
        if ("mindspore".equals(packageUrlVo.getNamespace())) {
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL(packageUrlVo.getType(),
                    packageUrlVo.getNamespace(), packageUrlVo.getName(), "v" + packageUrlVo.getVersion(), null, null)));
        } else if (packageUrlVo.getType() != null && packageUrlVo.getType().contains("git")) {
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(),
                    packageUrlVo.getName(), packageUrlVo.getVersion(), null, null)));
        } else {
            return null;
        }
    }

    /***
     * change OpenHarmony purl format to get license
     * for example:
     * pkg:gitee/openharmony/libxml2@2.9.10 -> pkg:gitee/openharmony/third_party_libxml2@OpenHarmony-v3.1-Release
     * pkg:gitee/openharmony/customization_enterprise_device_management@3.1-Release -> pkg:gitee/openharmony/customization_enterprise_device_management@OpenHarmony-v3.1-Release
     ***/
    private String dealOpenHarmonyPurl(PackageUrlVo packageUrlVo, Product product) throws MalformedPackageURLException {
        if (!"gitee".equals(packageUrlVo.getType())) {
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(),
                    packageUrlVo.getName(), packageUrlVo.getVersion(), null, null)));
        } else {
            String repoName = packageUrlVo.getName();
            String version = packageUrlVo.getVersion();
            Optional<RepoMeta> repoMetaOptional = repoMetaRepository.findByProductNameAndPackageName(product.getName(), packageUrlVo.getName());
            if (repoMetaOptional.isPresent() && StringUtils.isNotEmpty(repoMetaOptional.get().getRepoName())) {
                repoName = repoMetaOptional.get().getRepoName();
                version = repoMetaOptional.get().getBranch();
            }
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(),
                    repoName, version, null, null)));
        }
    }

}
