package org.opensourceway.sbom.analyzer.pkggen;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.vcs.VcsService;
import org.opensourceway.sbom.model.enums.VcsEnum;
import org.opensourceway.sbom.model.pojo.vo.vcs.RepoInfo;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.ossreviewtoolkit.model.Hash;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Component("vcs")
public class VcsPackageGenerator extends AbstractPackageGenerator {
    private static final Logger logger = LoggerFactory.getLogger(VcsPackageGenerator.class);

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

    @Override
    public CuratedPackage generatePackage(String host, String path, String url) {
        String dirPattern = "/(.*?)/(.*?)/.*/(\\D*([.\\-_\\da-zA-Z]*))/.*";
        String packagePattern = "/(.*?)/(.*?)/.*/(\\2?\\D*([.\\-_\\da-zA-Z]*))";
        for (String pattern : Arrays.asList(dirPattern, packagePattern)) {
            Matcher matcher = Pattern.compile(pattern).matcher(path);
            if (matcher.matches()) {
                String org = matcher.group(1);
                String repo = matcher.group(2);
                String tag = matcher.group(3);
                String version = matcher.group(4);
                if (Pattern.compile("[a-zA-Z]*").matcher(tag).matches()) {
                    continue;
                }
                if (Stream.of(org, repo, tag, version).allMatch(StringUtils::isNotEmpty)) {
                    return generatePackageFromVcs(host, org, repo, tag, "", tag, url);
                }
            }
        }

        return null;
    }

    public CuratedPackage generatePackageFromVcs(String host, String org, String repo, String version,
                                                 String commitId, String tag, String url) {
        logger.info("start to generate package from vcs for [host: '{}', org: '{}', repo: '{}']", host, org, repo);

        VcsEnum vcsEnum = VcsEnum.findVcsEnumByHost(host);
        if (Objects.isNull(vcsEnum) || !vcsServices.containsKey(vcsEnum)) {
            logger.warn("invalid vcs: '{}'", host);
            return null;
        }

        VcsService vcsService = vcsServices.get(vcsEnum);
        RepoInfo repoInfo = vcsService.getRepoInfo(org, repo);
        String sourceUrl = getSourceUrl(org, repo, commitId, tag, url, vcsService);
        String revision = StringUtils.isEmpty(tag) ? commitId : tag;
        Identifier identifier = new Identifier(vcsEnum.name().toLowerCase(), org, repo, version);
        VcsInfo vcsInfo = new VcsInfo(VcsType.Companion.getGIT(), repoInfo.repoUrl(), revision, "");
        Package pkg = new Package(identifier, ExtensionsKt.toPurl(identifier), "", repoInfo.authors(),
                repoInfo.licenses(), ProcessedDeclaredLicense.EMPTY, null, repoInfo.description(),
                repoInfo.homepageUrl(), RemoteArtifact.EMPTY, new RemoteArtifact(sourceUrl, Hash.Companion.getNONE()),
                vcsInfo, vcsInfo.normalize(), false, false);
        logger.info("successfully generated package from vcs for [host: '{}', org: '{}', repo: '{}']", host, org, repo);
        return new CuratedPackage(pkg, new ArrayList<>());
    }

    private String getSourceUrl(String org, String repo, String commitId, String tag, String url, VcsService vcsService) {
        if (StringUtils.isNotEmpty(url)) {
            return url;
        }

        if (StringUtils.isNotEmpty(tag)) {
            return vcsService.getTagDownloadUrl(org, repo, tag);
        }

        return vcsService.getCommitUrl(org, repo, commitId);
    }
}
