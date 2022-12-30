package org.opensourceway.sbom.batch.processor.sourceinfo;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.cache.OpenEulerRepoMetaCache;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.enums.SbomFileType;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.pojo.vo.sbom.SupplySourceInfo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.core.ExitStatus;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.StepExecutionListener;
import org.springframework.batch.item.ExecutionContext;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class SupplySourceInfoProcessor implements ItemProcessor<List<UUID>, SupplySourceInfo>, StepExecutionListener {

    private static final Logger logger = LoggerFactory.getLogger(SupplySourceInfoProcessor.class);

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Autowired
    private OpenEulerRepoMetaCache openEulerUpstreamCache;

    private StepExecution stepExecution;

    private ExecutionContext jobContext;

    @Nullable
    @Override
    public SupplySourceInfo process(List<UUID> pkgIdList) {
        UUID sbomId = this.jobContext.containsKey(BatchContextConstants.BATCH_SBOM_ID_KEY) ?
                (UUID) this.jobContext.get(BatchContextConstants.BATCH_SBOM_ID_KEY) : null;
        String productVersion = stepExecution.getExecutionContext().getString(BatchContextConstants.BATCH_PRODUCT_VERSION_KEY);
        String productType = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY);

        logger.info("start SupplySourceInfoProcessor sbomId:{}, productType:{}, productVersion:{}, first pkg id:{}",
                sbomId, productType, productVersion, pkgIdList.get(0).toString());

        SupplySourceInfo supplySourceInfo = new SupplySourceInfo();
        List<String> noRepoMetaPkgList = new ArrayList<>();

        pkgIdList.forEach(pkgId -> {
            try {
                Optional<Package> packageOptional = packageRepository.findById(pkgId);
                if (packageOptional.isEmpty()) {
                    logger.error("can't find {} package", pkgId);
                    return;
                }
                Package pkg = packageOptional.get();
                getRepoMeta(productVersion, pkg.getName()).ifPresentOrElse(repoMeta -> {
                    supplyDownloadLocation(supplySourceInfo, pkg, repoMeta);
                    supplyUpstream(supplySourceInfo, pkg, repoMeta);
                    supplyPatchInfo(supplySourceInfo, pkg, repoMeta);
                }, () -> noRepoMetaPkgList.add(pkg.getName()));
            } catch (Exception e) {
                logger.error("SupplySourceInfoProcessor failed, package id:{}", pkgId, e);
                throw new RuntimeException(e);
            }
        });

        if (!ObjectUtils.isEmpty(noRepoMetaPkgList)) {
            logger.warn("SupplySourceInfoStep can't find package's repoMeta, sbomId:{}, branch:{}, pkgName list:{}",
                    sbomId,
                    productVersion,
                    noRepoMetaPkgList);
        }

        logger.info("finish SupplySourceInfoProcessor sbomId:{}", sbomId);
        return supplySourceInfo;
    }

    private Optional<RepoMeta> getRepoMeta(String productVersion, String pkgName) {
        String productType = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY);
        if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENEULER_NAME)) {
            return repoMetaRepository.queryRepoMetaByPackageName(productType, productVersion, pkgName)
                    .stream().findFirst();
        } else if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)) {
            String productName = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_NAME_KEY);
            return repoMetaRepository.findByProductNameAndPackageName(productName, pkgName);
        }
        return Optional.empty();
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

    private void supplyDownloadLocation(SupplySourceInfo supplySourceInfo, Package pkg, RepoMeta repoMeta) {
        pkg.setDownloadLocation(repoMeta.getDownloadLocation());
        supplySourceInfo.addPkg(pkg);
    }

    private void supplyUpstream(SupplySourceInfo supplySourceInfo, Package pkg, RepoMeta repoMeta) {
        String productType = jobContext.getString(BatchContextConstants.BATCH_SBOM_PRODUCT_TYPE_KEY);
        if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENEULER_NAME)) {
            supplyUpstreamForOpenEuler(supplySourceInfo, pkg, repoMeta);
        } else if (StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)) {
            supplyUpstreamForOpenHarmony(supplySourceInfo, pkg, repoMeta);
        }
    }

    private void supplyUpstreamForOpenEuler(SupplySourceInfo supplySourceInfo, Package pkg, RepoMeta repoMeta) {
        if (pkg.getExternalPurlRefs() == null) {
            pkg.setExternalPurlRefs(new ArrayList<>());
        }

        RepoMeta openEulerRepoMeta = openEulerUpstreamCache.getRepoMeta(repoMeta.getRepoName(), repoMeta.getBranch());
        if (openEulerRepoMeta == null || CollectionUtils.isEmpty(openEulerRepoMeta.getUpstreamUrls())) {
            return;
        }

        for (String upstreamLocation : openEulerRepoMeta.getUpstreamUrls()) {
            try {
                ExternalPurlRef upstreamPurl = new ExternalPurlRef();
                upstreamPurl.setCategory(ReferenceCategory.SOURCE_MANAGER.name());
                upstreamPurl.setType(ReferenceType.URL.getType());
                upstreamPurl.setPkg(pkg);

                PackageUrlVo vo = new PackageUrlVo();
                vo.setType("upstream");
                vo.setName(upstreamLocation);
                upstreamPurl.setPurl(vo);
                if (pkg.getExternalPurlRefs().contains(upstreamPurl)) {
                    logger.warn("upstreamPurl:{} has existed in package:{}", upstreamPurl.getPurl(), pkg.getId());
                    continue;
                }
                pkg.getExternalPurlRefs().add(upstreamPurl);
            } catch (Exception e) {
                logger.error("supplyUpstream for openEuler failed, package:{}", pkg.getId(), e);
                throw new RuntimeException(e);
            }
        }
    }

    private void supplyUpstreamForOpenHarmony(SupplySourceInfo supplySourceInfo, Package pkg, RepoMeta repoMeta) {
        String upstreamUrl = (String) Optional.ofNullable(repoMeta.getExtendedAttr())
                .map(it -> it.get(SbomRepoConstants.UPSTREAM_URL)).orElse(null);
        if (StringUtils.isEmpty(upstreamUrl)) {
            return;
        }
        if (pkg.getExternalPurlRefs() == null) {
            pkg.setExternalPurlRefs(new ArrayList<>());
        }

        try {
            ExternalPurlRef upstreamPurl = new ExternalPurlRef();
            upstreamPurl.setCategory(ReferenceCategory.SOURCE_MANAGER.name());
            upstreamPurl.setType(ReferenceType.URL.getType());
            upstreamPurl.setPkg(pkg);

            PackageUrlVo vo = new PackageUrlVo();
            vo.setType("upstream");
            vo.setName(upstreamUrl);
            upstreamPurl.setPurl(vo);
            if (pkg.getExternalPurlRefs().contains(upstreamPurl)) {
                logger.warn("upstreamPurl: {} already exists in package: {}", upstreamPurl.getPurl(), pkg.getId());
                return;
            }
            pkg.getExternalPurlRefs().add(upstreamPurl);
        } catch (Exception e) {
            logger.error("supplyUpstream failed, upstream:{}", upstreamUrl, e);
            throw new RuntimeException(e);
        }
    }

    private void supplyPatchInfo(SupplySourceInfo supplySourceInfo, Package pkg, RepoMeta repoMeta) {
        if (ArrayUtils.isEmpty(repoMeta.getPatchInfo())) {
            return;
        }

        for (String patchName : repoMeta.getPatchInfo()) {
            File file = new File();
            file.setSbom(pkg.getSbom());
            file.setSpdxId(repoMeta.getRepoName() + "-" + patchName);
            file.setFileName(SbomConstants.OPENEULER_PATCH_INFO_URL_PATTERN
                    .formatted(giteeApi.getDefaultBaseUrl(),
                            SbomRepoConstants.OPENEULER_REPO_ORG,
                            repoMeta.getRepoName(),
                            repoMeta.getBranch(),
                            patchName));
            file.setFileTypes(new String[]{SbomFileType.SOURCE.name()});
            supplySourceInfo.addFile(file);

            SbomElementRelationship relationship = new SbomElementRelationship();
            relationship.setSbom(pkg.getSbom());
            relationship.setElementId(file.getSpdxId());
            relationship.setRelatedElementId(pkg.getSpdxId());
            relationship.setRelationshipType(RelationshipType.PATCH_APPLIED.name());
            supplySourceInfo.addRelationship(relationship);
        }
    }

}
