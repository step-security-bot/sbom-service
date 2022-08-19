package org.openeuler.sbom.analyzer.utils;

import org.apache.commons.lang3.StringUtils;
import org.openeuler.sbom.analyzer.model.RepoInfo;
import org.openeuler.sbom.analyzer.vcs.VcsService;
import org.openeuler.sbom.clients.vcs.VcsEnum;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.ossreviewtoolkit.model.Identifier;
import org.ossreviewtoolkit.model.Package;
import org.ossreviewtoolkit.model.RemoteArtifact;
import org.ossreviewtoolkit.model.VcsInfo;
import org.ossreviewtoolkit.model.VcsType;
import org.ossreviewtoolkit.model.utils.ExtensionsKt;
import org.ossreviewtoolkit.utils.ort.ProcessedDeclaredLicense;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class PackageGenerator {
    private static final Logger logger = LoggerFactory.getLogger(PackageGenerator.class);

    @Autowired
    private Map<String, VcsService> hostToVcsService;

    private Map<VcsEnum, VcsService> vcsServices;

    @PostConstruct
    private void convertVcsApis() {
        vcsServices = new HashMap<>();
        hostToVcsService.forEach((host, service) -> {
            VcsEnum vcsEnum = VcsEnum.findVcsEnumByHost(host);
            vcsServices.put(Objects.requireNonNull(vcsEnum, "vcs service of %s is not in VcsEnum".formatted(host)), service);
        });
    }

    public CuratedPackage generatePackageFromVcs(String host, String org, String repo, String version,
                                                 String commitId, String tag) {
        logger.info("start to generate package from vcs for [host: '{}', org: '{}', repo: '{}']", host, org, repo);

        VcsEnum vcsEnum = VcsEnum.findVcsEnumByHost(host);
        if (Objects.isNull(vcsEnum) || !vcsServices.containsKey(vcsEnum)) {
            logger.warn("invalid vcs: '{}'", host);
            return null;
        }

        RepoInfo repoInfo = vcsServices.get(vcsEnum).getRepoInfo(org, repo);
        String revision = StringUtils.isEmpty(tag) ? commitId : tag;
        Identifier identifier = new Identifier(vcsEnum.name().toLowerCase(), org, repo, version);
        VcsInfo vcsInfo = new VcsInfo(VcsType.Companion.getGIT(), repoInfo.repoUrl(), revision, "");
        Package vcsPackage = new Package(identifier, ExtensionsKt.toPurl(identifier), "", repoInfo.authors(),
                repoInfo.licenses(), ProcessedDeclaredLicense.EMPTY, null, repoInfo.description(),
                repoInfo.homepageUrl(), RemoteArtifact.EMPTY, RemoteArtifact.EMPTY, vcsInfo, vcsInfo.normalize(),
                false, false);
        logger.info("successfully generated package from vcs for [host: '{}', org: '{}', repo: '{}']", host, org, repo);
        return new CuratedPackage(vcsPackage, new ArrayList<>());
    }
}
