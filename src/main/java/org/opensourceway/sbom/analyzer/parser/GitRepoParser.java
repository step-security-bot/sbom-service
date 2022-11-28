package org.opensourceway.sbom.analyzer.parser;

import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.model.GitRepoDefault;
import org.opensourceway.sbom.analyzer.model.GitRepoManifest;
import org.opensourceway.sbom.analyzer.model.GitRepoProject;
import org.opensourceway.sbom.analyzer.model.GitRepoRemote;
import org.opensourceway.sbom.analyzer.pkggen.VcsPackageGenerator;
import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.constants.BatchContextConstants;
import org.opensourceway.sbom.constants.PublishSbomConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.RepoMetaRepository;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.RepoMeta;
import org.opensourceway.sbom.utils.Mapper;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.ossreviewtoolkit.model.Identifier;
import org.ossreviewtoolkit.model.Package;
import org.ossreviewtoolkit.model.utils.ExtensionsKt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
public class GitRepoParser {

    private static final Logger logger = LoggerFactory.getLogger(GitRepoParser.class);

    private static final String THIRD_PARTY_REPO_PREFIX = "third_party_";

    @Autowired
    private VcsPackageGenerator vcsPackageGenerator;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Value("${gitee.domain.url}")
    private String giteeDomainUrl;

    public Set<CuratedPackage> parse(Path gitRepoDirPath) throws IOException {
        Path defaultManifest = Paths.get(gitRepoDirPath.toString(), PublishSbomConstants.GIT_REPO_DEFAULT_MANIFEST);
        if (!Files.isRegularFile(defaultManifest)) {
            throw new RuntimeException("[%s] doesn't exist or is not a regular file".formatted(
                    PublishSbomConstants.GIT_REPO_DEFAULT_MANIFEST));
        }

        GitRepoManifest manifest = Mapper.xmlMapper.readValue(defaultManifest.toFile(), GitRepoManifest.class);
        Map<String, GitRepoRemote> nameToRemote = manifest.getRemotes().stream()
                .collect(Collectors.toMap(GitRepoRemote::getName, Function.identity()));
        validate(manifest, nameToRemote);

        return manifest.getProjects().stream()
                .map(project -> getPackage(project, manifest.getManifestDefault().get(0), nameToRemote))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    private void validate(GitRepoManifest manifest, Map<String, GitRepoRemote> nameToRemote) {
        manifest.getProjects().forEach(project -> {
            if (Objects.isNull(project.getName())) {
                throw new RuntimeException("Some projects lack of 'name' attribute");
            }
        });

        manifest.getProjects().stream()
                .collect(Collectors.groupingBy(GitRepoProject::getName, Collectors.counting()))
                .forEach((name, count) -> {
                    if (count > 1) {
                        throw new RuntimeException("Duplicate project name: %s".formatted(name));
                    }
                });

        manifest.getRemotes().forEach(remote -> {
            if (Objects.isNull(remote.getName())) {
                throw new RuntimeException("Some remotes lack of 'name' attribute");
            }
        });

        manifest.getRemotes().stream()
                .collect(Collectors.groupingBy(GitRepoRemote::getName, Collectors.counting()))
                .forEach((name, count) -> {
                    if (count > 1) {
                        throw new RuntimeException("Duplicate remote name: %s".formatted(name));
                    }
                });

        manifest.getRemotes().forEach(remote -> {
            if (Objects.isNull(remote.getFetch())) {
                throw new RuntimeException("Some remotes lack of 'fetch' attribute");
            }
        });

        if (manifest.getManifestDefault().size() > 1) {
            throw new RuntimeException("Multiple default element in manifest");
        }

        GitRepoDefault gitRepoDefault = manifest.getManifestDefault().get(0);
        if (Objects.nonNull(gitRepoDefault) && Objects.nonNull(gitRepoDefault.getRemote())
                && !nameToRemote.containsKey(gitRepoDefault.getRemote())) {
            throw new RuntimeException("Remote [%s] of default doesn't exist".formatted(gitRepoDefault.getRemote()));
        }

        Set<String> referencedRemotes = manifest.getProjects().stream()
                .map(GitRepoProject::getRemote)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        if (!nameToRemote.keySet().containsAll(referencedRemotes)) {
            referencedRemotes.removeAll(nameToRemote.keySet());
            throw new RuntimeException("All referenced remotes by projects are not defined in manifest: %s".formatted(referencedRemotes));
        }
    }

    private CuratedPackage getPackage(GitRepoProject project, GitRepoDefault manifestDefault, Map<String, GitRepoRemote> nameToRemote) {
        GitRepoRemote remote = getRemote(project, manifestDefault, nameToRemote);
        String url = getUrl(project, remote);
        Matcher matcher = Pattern.compile("https://(.*)/(.*)/(.*)").matcher(url);
        if (!matcher.matches()) {
            throw new RuntimeException("invalid project url: '%s'".formatted(url));
        }
        String host = matcher.group(1);
        String org = matcher.group(2);
        String repo = matcher.group(3);

        String revision = Optional.ofNullable(Optional.ofNullable(project.getRevision()).orElse(remote.getRevision()))
                .orElse(manifestDefault.getRevision());
        String upstream = Optional.ofNullable(project.getUpstream()).orElse(manifestDefault.getUpstream());
        String tag = null;
        String commitId = null;
        if (revision.contains("refs/tags/")) {
            tag = revision.replace("refs/tags/", "");
        } else if (upstream.contains("refs/tags/")) {
            tag = upstream.replace("refs/tags/", "");
        }
        if (Pattern.compile("[\\da-z]{40}").matcher(revision).matches()) {
            commitId = revision;
        }
        if (Objects.isNull(tag) && Objects.isNull(commitId)) {
            throw new RuntimeException("No tag or commit id is provided for project [%s]".formatted(project.getName()));
        }
        if (Objects.isNull(tag)) {
            return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, commitId, commitId, null, url);
        }

        String version = tag;
        matcher = Pattern.compile("\\D*([.\\-_\\da-zA-Z]*)").matcher(tag);
        if (matcher.matches()) {
            version = matcher.group(1);
        }
        return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, version, commitId, tag, url);
    }

    private GitRepoRemote getRemote(GitRepoProject project, GitRepoDefault manifestDefault, Map<String, GitRepoRemote> nameToRemote) {
        String remote = project.getRemote();
        if (Objects.nonNull(remote)) {
            return nameToRemote.get(remote);
        }

        if (Objects.isNull(manifestDefault) || Objects.isNull(manifestDefault.getRemote())) {
            throw new RuntimeException(("Project [%s] doesn't have remote attribute, and there is no default element " +
                    "in manifest or no remote attribute in default element").formatted(project.getName()));
        }
        return nameToRemote.get(manifestDefault.getRemote());
    }

    private String getUrl(GitRepoProject project, GitRepoRemote remote) {
        String remoteUrl = getRemoteUrl(remote);
        return URI.create(remoteUrl).resolve(project.getName()).toString();
    }

    private String getRemoteUrl(GitRepoRemote remote) {
        for (String url: List.of(remote.getFetch(), remote.getReview())) {
            Matcher matcher = Pattern.compile("https://.*").matcher(url);
            if (matcher.matches()) {
                return url.replaceAll("https://.*\\.gitee\\.com", giteeDomainUrl);
            }
        }
        throw new RuntimeException("Can't get url from remote [%s]".formatted(remote.getName()));
    }

    public Set<CuratedPackage> correctPackageNameVersion(String productName, Set<CuratedPackage> packages) {
        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));
        String productType = product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_TYPE_KEY);

        Set<CuratedPackage> correctedPackages = new HashSet<>();
        packages.stream()
                .map(CuratedPackage::getPkg)
                .filter(pkg -> StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)
                        && pkg.getId().getName().startsWith(THIRD_PARTY_REPO_PREFIX))
                .forEach(pkg -> {
                    logger.info("Convert name and version for OpenHarmony third packages: {}", pkg.getId().getName());
                    handleOpenHarmonyThirdPartyRepo(productType, pkg, correctedPackages);
                });

        packages.stream()
                .map(CuratedPackage::getPkg)
                .filter(pkg -> !StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)
                        || !pkg.getId().getName().startsWith(THIRD_PARTY_REPO_PREFIX))
                .forEach(pkg -> correctedPackages.add(pkg.toCuratedPackage()));

        return correctedPackages;
    }

    private void handleOpenHarmonyThirdPartyRepo(String productType, Package pkg, Set<CuratedPackage> correctedPackages) {
        RepoMeta repoMeta = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(productType, pkg.getId().getName(), pkg.getVcs().getRevision())
                .orElse(null);

        if (Objects.isNull(repoMeta)) {
            correctedPackages.add(pkg.toCuratedPackage());
            return;
        }

        Identifier identifier = new Identifier(pkg.getId().getType(), pkg.getId().getNamespace(),
                getUpstreamName(pkg, repoMeta), getUpstreamVersion(pkg, repoMeta));

        Package correctedPkg = new Package(identifier, ExtensionsKt.toPurl(identifier), "", pkg.getAuthors(),
                pkg.getDeclaredLicenses(), pkg.getDeclaredLicensesProcessed(), pkg.getConcludedLicense(), pkg.getDescription(),
                pkg.getHomepageUrl(), pkg.getBinaryArtifact(), pkg.getSourceArtifact(),
                pkg.getVcs(), pkg.getVcsProcessed(), pkg.isMetaDataOnly(), pkg.isModified());
        correctedPackages.add(correctedPkg.toCuratedPackage());
    }

    private String getUpstreamName(Package pkg, RepoMeta repoMeta) {
        String upstreamName = getUpstreamInfo(pkg.getId().getName().replace(THIRD_PARTY_REPO_PREFIX, ""), repoMeta).get("upstream_name");
        return ObjectUtils.isEmpty(upstreamName) ? pkg.getId().getName() : upstreamName;
    }

    private String getUpstreamVersion(Package pkg, RepoMeta repoMeta) {
        String upstreamVersion = getUpstreamInfo(pkg.getId().getName().replace(THIRD_PARTY_REPO_PREFIX, ""), repoMeta).get("upstream_version");
        return ObjectUtils.isEmpty(upstreamVersion) ? pkg.getId().getVersion() : upstreamVersion;
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> getUpstreamInfo(String pkgName, RepoMeta repoMeta) {
        return (Map<String, String>) Optional.ofNullable(repoMeta.getExtendedAttr())
                .map(it -> it.getOrDefault(pkgName, Map.of())).orElse(Map.of());
    }
}
