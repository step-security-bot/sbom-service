package org.opensourceway.sbom.manager.service.license.impl;

import com.github.packageurl.MalformedPackageURLException;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.service.license.LicenseService;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.opensourceway.sbom.openeuler.obs.SbomRepoConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.Arrays;
import java.util.List;

@Service
@Qualifier("LicenseServiceImpl")
@Transactional(rollbackFor = Exception.class)
public class LicenseServiceImpl implements LicenseService {
    private static final Logger logger = LoggerFactory.getLogger(LicenseServiceImpl.class);

    @Autowired
    private RepoMetaRepository repoMetaRepository;

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
                    String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY)), packageUrlVo.getName());
            String repoName = packageUrlVo.getName();
            if (!CollectionUtils.isEmpty(repoMetaList) && !repoMetaList.get(0).getDownloadLocation().isEmpty()) {
                String downloadLocation = repoMetaList.get(0).getDownloadLocation();
                List<String> repoInfo = Arrays.stream(Arrays.stream(downloadLocation.split("/tree/")).toList().get(0).split("/")).toList();
                repoName = repoInfo.get(repoInfo.size() - 1);
            }
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL("gitee", SbomRepoConstants.OPENEULER_REPO_ORG,
                    repoName, String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY)),
                    null, null)));

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
            List<RepoMeta> repoMetaList = repoMetaRepository.queryRepoMetaByPackageName(SbomConstants.PRODUCT_OPENHARMONY_NAME,
                    String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY)), packageUrlVo.getName());
            String repoName = packageUrlVo.getName();
            if (!CollectionUtils.isEmpty(repoMetaList) && !repoMetaList.get(0).getRepoName().isEmpty()) {
                repoName = repoMetaList.get(0).getRepoName();
            }
            return (PurlUtil.canonicalizePurl(PurlUtil.newPackageURL(packageUrlVo.getType(), packageUrlVo.getNamespace(),
                    repoName, String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY)),
                    null, null)));
        }
    }

    public String getPurlsForLicense(PackageUrlVo packageUrlVo, Product product) {
        String purl = "";
        String productType = String.valueOf(product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_TYPE_KEY));
        try {

            if (SbomConstants.PRODUCT_MINDSPORE_NAME.equals(productType)) {
                purl = dealMindsporePurl(packageUrlVo);
            } else if (SbomConstants.PRODUCT_OPENEULER_NAME.equals(productType)) {
                purl = dealOpenEulerPurl(packageUrlVo, product);
            } else if (SbomConstants.PRODUCT_OPENHARMONY_NAME.equals(productType)) {
                purl = dealOpenHarmonyPurl(packageUrlVo, product);
            }
        } catch (MalformedPackageURLException e) {
            logger.error("failed to get purl for License ");
            return null;
        }
        return purl;
    }

}
