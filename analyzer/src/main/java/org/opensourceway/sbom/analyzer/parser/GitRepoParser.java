package org.opensourceway.sbom.analyzer.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.pkggen.VcsPackageGenerator;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.RepoMetaRepository;
import org.opensourceway.sbom.model.constants.BatchContextConstants;
import org.opensourceway.sbom.model.constants.PublishSbomConstants;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.opensourceway.sbom.model.pojo.vo.analyzer.GitRepoDefault;
import org.opensourceway.sbom.model.pojo.vo.analyzer.GitRepoManifest;
import org.opensourceway.sbom.model.pojo.vo.analyzer.GitRepoProject;
import org.opensourceway.sbom.model.pojo.vo.analyzer.GitRepoRemote;
import org.opensourceway.sbom.model.pojo.vo.repo.ThirdPartyMetaVo;
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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
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

    @Autowired
    private VcsPackageGenerator vcsPackageGenerator;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Value("${gitee.domain.url}")
    private String giteeDomainUrl;

    @Autowired
    private RepoMetaRepository repoMetaRepository;

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
        String tag = getTag(revision, upstream);
        String commitId = getCommitId(revision);

        if (Objects.isNull(tag) && Objects.isNull(commitId)) {
            throw new RuntimeException("No tag or commit id is provided for project [%s]".formatted(project.getName()));
        }
        if (Objects.isNull(tag) || Pattern.compile("[\\da-z]{40}").matcher(tag).matches()) {
            return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, commitId, commitId, null, url);
        }

        return vcsPackageGenerator.generatePackageFromVcs(host, org, repo, tag, commitId, tag, url);
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

    private String getTag(String revision, String upstream) {
        if (upstream.contains("refs/tags/")) {
            return upstream.replace("refs/tags/", "");
        }
        if (revision.contains("refs/tags/")) {
            return revision.replace("refs/tags/", "");
        }
        if (StringUtils.isNotEmpty(upstream)) {
            return upstream;
        }
        if (StringUtils.isNotEmpty(revision)) {
            return revision;
        }
        return null;
    }

    private String getCommitId(String revision) {
        return Pattern.compile("[\\da-z]{40}").matcher(revision).matches() ? revision : null;
    }

    public Set<CuratedPackage> correctPackageNameVersion(String productName, Set<CuratedPackage> packages) {
        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));
        String productType = product.getAttribute().get(BatchContextConstants.BATCH_PRODUCT_TYPE_KEY);

        Set<CuratedPackage> correctedPackages = new HashSet<>();
        Set<RepoMeta> repoMetas = new HashSet<>();
        repoMetaRepository.deleteByProductName(productName);

        packages.stream()
                .map(CuratedPackage::getPkg)
                .filter(pkg -> StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)
                        && pkg.getId().getName().startsWith(SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_REPO_PREFIX))
                .forEach(pkg -> {
                    logger.info("Convert name and version for OpenHarmony third packages: {}", pkg.getId().getName());
                    handleOpenHarmonyThirdPartyRepo(pkg, correctedPackages, repoMetas, productName);
                });

        packages.stream()
                .map(CuratedPackage::getPkg)
                .filter(pkg -> !StringUtils.equalsIgnoreCase(productType, SbomConstants.PRODUCT_OPENHARMONY_NAME)
                        || !pkg.getId().getName().startsWith(SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_REPO_PREFIX))
                .forEach(pkg -> handleOpenHarmonyNonThirdPartyRepo(pkg, correctedPackages, repoMetas, productName));

        repoMetaRepository.saveAll(repoMetas);

        return correctedPackages;
    }

    private void handleOpenHarmonyThirdPartyRepo(Package pkg, Set<CuratedPackage> correctedPackages, Set<RepoMeta> repoMetas,
                                                 String productName) {
        try {
            String thirdPartyMetaUrl = MessageFormat.format("{0}/{1}/{2}/raw/{3}/{4}",
                    giteeDomainUrl, SbomRepoConstants.OPEN_HARMONY_GITEE_ORG, pkg.getId().getName(), pkg.getVcs().getRevision(),
                    SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_META_FILE);
            String thirdPartyMeta = giteeApi.getFileContext(thirdPartyMetaUrl);
            List<ThirdPartyMetaVo> vos = Mapper.jsonMapper.readValue(thirdPartyMeta, new TypeReference<>() {});
            Identifier identifier = new Identifier(pkg.getId().getType(), pkg.getId().getNamespace(),
                    pkg.getId().getName().replace(SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_REPO_PREFIX, ""),
                    StringUtils.isEmpty(vos.get(0).getVersion().strip()) ? pkg.getId().getVersion() : vos.get(0).getVersion().strip());
            Package correctedPkg = new Package(identifier, ExtensionsKt.toPurl(identifier), "", pkg.getAuthors(),
                    pkg.getDeclaredLicenses(), pkg.getDeclaredLicensesProcessed(), pkg.getConcludedLicense(), pkg.getDescription(),
                    pkg.getHomepageUrl(), pkg.getBinaryArtifact(), pkg.getSourceArtifact(),
                    pkg.getVcs(), pkg.getVcsProcessed(), pkg.isMetaDataOnly(), pkg.isModified());
            correctedPackages.add(correctedPkg.toCuratedPackage());

            RepoMeta repoMeta = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(
                    SbomConstants.PRODUCT_OPENHARMONY_NAME, pkg.getId().getName(), pkg.getVcs().getRevision()).orElse(new RepoMeta());
            repoMeta.setProductType(SbomConstants.PRODUCT_OPENHARMONY_NAME);
            repoMeta.setRepoName(pkg.getId().getName());
            repoMeta.setBranch(pkg.getVcs().getRevision());
            repoMeta.setPackageNames(new String[]{correctedPkg.getId().getName()});
            repoMeta.setDownloadLocation(MessageFormat.format("{0}/{1}/{2}/tree/{3}",
                    giteeDomainUrl, SbomRepoConstants.OPEN_HARMONY_GITEE_ORG, pkg.getId().getName(), pkg.getVcs().getRevision()));
            repoMeta.setExtendedAttr(Map.of(SbomRepoConstants.UPSTREAM_URL, vos.get(0).getUpstreamUrl().strip(),
                    SbomConstants.PRODUCT_NAME, productName));
            repoMetas.add(repoMeta);
        } catch (JsonProcessingException e) {
            logger.warn("The {} of repo [{}] with version [{}] is invalid",
                    SbomRepoConstants.OPEN_HARMONY_THIRD_PARTY_META_FILE, pkg.getId().getName(), pkg.getVcs().getRevision());
            handleOpenHarmonyNonThirdPartyRepo(pkg, correctedPackages, repoMetas, productName);
        } catch (RuntimeException e) {
            logger.warn("Unknown exception occurs when fetch repo meta for repo [{}] with version [{}]",
                    pkg.getId().getName(), pkg.getVcs().getRevision(), e);
            handleOpenHarmonyNonThirdPartyRepo(pkg, correctedPackages, repoMetas, productName);
        }

    }

    private void handleOpenHarmonyNonThirdPartyRepo(Package pkg, Set<CuratedPackage> correctedPackages, Set<RepoMeta> repoMetas,
                                                    String productName) {
        RepoMeta repoMeta = repoMetaRepository.findByProductTypeAndRepoNameAndBranch(
                SbomConstants.PRODUCT_OPENHARMONY_NAME, pkg.getId().getName(), pkg.getVcs().getRevision()).orElse(new RepoMeta());
        repoMeta.setProductType(SbomConstants.PRODUCT_OPENHARMONY_NAME);
        repoMeta.setRepoName(pkg.getId().getName());
        repoMeta.setBranch(pkg.getVcs().getRevision());
        repoMeta.setPackageNames(new String[]{pkg.getId().getName()});
        repoMeta.setDownloadLocation(MessageFormat.format("{0}/{1}/{2}/tree/{3}",
                giteeDomainUrl, SbomRepoConstants.OPEN_HARMONY_GITEE_ORG, pkg.getId().getName(), pkg.getVcs().getRevision()));
        repoMeta.setExtendedAttr(Map.of(SbomConstants.PRODUCT_NAME, productName));
        repoMetas.add(repoMeta);

        correctedPackages.add(pkg.toCuratedPackage());
    }
}
