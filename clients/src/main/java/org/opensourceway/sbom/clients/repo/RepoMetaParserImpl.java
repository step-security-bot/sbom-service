package org.opensourceway.sbom.clients.repo;

import com.google.common.collect.Multimap;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.computer.whunter.rpm.parser.RpmSpecParser;
import org.opensourceway.sbom.api.repo.RepoMetaParser;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.cache.OpenEulerRepoBranchCache;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.constants.SbomRepoConstants;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeBranchInfo;
import org.opensourceway.sbom.model.pojo.response.vcs.gitee.GiteeFileInfo;
import org.opensourceway.sbom.model.pojo.vo.repo.MetaServiceDomain;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;


@Service
public class RepoMetaParserImpl implements RepoMetaParser {

    private static final Logger logger = LoggerFactory.getLogger(RepoMetaParserImpl.class);

    private static final String ZIP_ROOT_FOLDER_NAME = "obs_meta-master";

    private static final String UNZIP_TARGET_FOLDER_PREFIX_PATTERN = ZIP_ROOT_FOLDER_NAME
            .concat(SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR)
            .concat("%s")
            .concat(SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR);

    private static final String OPENEULER_META_FILE_NAME = "_service";

    private static final Pattern specFileNameRegex = Pattern.compile(SbomRepoConstants.SPEC_FILE_NAME_REGEX, Pattern.CASE_INSENSITIVE);

    private static final Pattern yamlFileNameRegex = Pattern.compile(SbomRepoConstants.YAML_FILE_NAME_REGEX, Pattern.CASE_INSENSITIVE);

    @Value("${openeuler.newest.versions}")
    private String[] openEulerNewestVersion;

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Autowired
    private OpenEulerRepoBranchCache openEulerRepoCache;

    @Override
    public Set<RepoInfoVo> fetchObsMetaSourceCode() throws IOException {
        File tmpDir = null;
        File tmpArchive = null;
        Set<RepoInfoVo> repoInfoSet;

        try {
            Path tmpDirPath = this.createTmpDir();
            logger.info("create download obs meta source temp dir:{}", tmpDirPath.toString());
            tmpDir = tmpDirPath.toFile();
            tmpDir.deleteOnExit();

            Path obsMetaArchive = giteeApi.downloadRepoArchive(tmpDirPath,
                    SbomRepoConstants.OPENEULER_REPO_ORG,
                    SbomRepoConstants.OBS_META_REPO_NAME,
                    SbomRepoConstants.OBS_META_REPO_BRANCH);
            logger.info("download obs meta archive path:{}", obsMetaArchive.toString());
            tmpArchive = obsMetaArchive.toFile();
            tmpArchive.deleteOnExit();

            repoInfoSet = parseRepoInfoFromZip(obsMetaArchive);
        } finally {
            if (tmpArchive != null) {
                boolean result = tmpArchive.delete();
                logger.info("download obs meta archive, delete result:{}", result);
            }
            if (tmpDir != null) {
                boolean result = tmpDir.delete();
                logger.info("download obs meta source temp dir, delete result:{}", result);
            }
        }

        return repoInfoSet;
    }

    @Override
    public Pair<Boolean, String> isRepoChanged(RepoInfoVo repoInfo, String lastCommitId) {
        try {
            List<GiteeBranchInfo.BranchInfo> branchList = openEulerRepoCache.getRepoBranches(SbomRepoConstants.OPENEULER_REPO_ORG, repoInfo.getRepoName());
            Optional<GiteeBranchInfo.BranchInfo> branchOptional = branchList.stream()
                    .filter(branch -> StringUtils.equalsIgnoreCase(branch.name(), repoInfo.getBranch())).findFirst();

            if (branchOptional.isEmpty()) {
                logger.warn("isRepoChanged repo name:{}, repo branch:{} can't be found in Gitee",
                        repoInfo.getRepoName(),
                        repoInfo.getBranch());
                return Pair.of(false, "");
            }
            if (StringUtils.isNotEmpty(branchOptional.get().commit().sha())
                    && !StringUtils.equalsIgnoreCase(branchOptional.get().commit().sha(), lastCommitId)) {
                return Pair.of(true, branchOptional.get().commit().sha());
            }
        } catch (WebClientResponseException.NotFound e) {
            logger.warn("isRepoChanged repo name:{} can't be found in Gitee", repoInfo.getRepoName());
            return Pair.of(false, "");
        } catch (Exception e) {
            logger.error("isRepoChanged repo name:{}, fetch repo branch info failed, failed info:",
                    repoInfo.getRepoName(),
                    e);
            return Pair.of(false, "");
        }
        return Pair.of(false, "");
    }

    /**
     * fetch repo's download url of spec file and yaml files
     */
    @Override
    public void fetchRepoBuildFileInfo(RepoInfoVo repoInfo) {
        try {
            List<GiteeFileInfo> allFileList = (List<GiteeFileInfo>) giteeApi.findRepoFiles(SbomRepoConstants.OPENEULER_REPO_ORG,
                    repoInfo.getRepoName(),
                    repoInfo.getBranch(),
                    SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR, null);

            Optional<GiteeFileInfo> specFileOptional = allFileList.stream()
                    .filter(file -> specFileNameRegex.matcher(file.name()).matches())
                    .findFirst();
            if (specFileOptional.isEmpty()) {
                return;
            }
            repoInfo.setSpecDownloadUrl(specFileOptional.get().downloadUrl());

            allFileList.stream()
                    .filter(file -> yamlFileNameRegex.matcher(file.name()).matches())
                    .forEach(yamlFile -> repoInfo.addUpstreamDownloadUrl(yamlFile.downloadUrl()));

            repoInfo.setDownloadLocation(SbomRepoConstants.OPENEULER_REPO_SOURCE_URL_PATTERN
                    .formatted(giteeApi.getDefaultBaseUrl(),
                            SbomRepoConstants.OPENEULER_REPO_ORG,
                            repoInfo.getRepoName(),
                            repoInfo.getBranch()));
        } catch (WebClientResponseException.NotFound e) {
            logger.warn("repo name:{}, repo branch:{} can't be found in Gitee",
                    repoInfo.getRepoName(),
                    repoInfo.getBranch());
            repoInfo.setLastCommitId(null);
        } catch (Exception e) {
            logger.error("repo name:{}, repo branch:{} fetch repo build file info failed, failed info:",
                    repoInfo.getRepoName(),
                    repoInfo.getBranch(),
                    e);
            repoInfo.setLastCommitId(null);
        }
    }

    @Override
    public void fetchRepoPackageAndPatchInfo(RepoInfoVo repoInfo) {
        try {
            if (StringUtils.isEmpty(repoInfo.getSpecDownloadUrl())) {
                logger.error("repo name:{}, spec url is empty", repoInfo.getRepoName());
                return;
            }

            String specContent = giteeApi.getFileContext(repoInfo.getSpecDownloadUrl());
            if (StringUtils.isEmpty(specContent)) {
                logger.error("repo name:{}, spec url:{}, is empty",
                        repoInfo.getRepoName(),
                        repoInfo.getSpecDownloadUrl());
                return;
            }

            Multimap<String, String> specProperties = RpmSpecParser.createParserByContent(specContent).parse();
            String rootPackageName = specProperties.get("name").stream().findFirst()
                    .orElseThrow(() -> new RuntimeException("repo name:%s, spec url:%s, spec name variable is null"
                            .formatted(repoInfo.getRepoName(), repoInfo.getSpecDownloadUrl())));
            repoInfo.addPackageName(rootPackageName);

            specProperties.forEach((String key, String value) -> {
                if (StringUtils.startsWith(key, "patch")) {
                    repoInfo.addPatch(value);
                } else if (StringUtils.equalsIgnoreCase(key, "%package")) {
                    if (StringUtils.contains(value, "-n")) {
                        repoInfo.addPackageName(value.split("-n", 2)[1].trim());
                    } else if (StringUtils.equalsIgnoreCase(value, "_help")) {
                        repoInfo.addPackageName(rootPackageName + "-help");
                    } else {
                        repoInfo.addPackageName(rootPackageName + "-" + value);
                    }
                }
            });
        } catch (Throwable e) {
            logger.error("repo name:{}, spec url:{}, fetch package and patch info failure:",
                    repoInfo.getRepoName(),
                    repoInfo.getSpecDownloadUrl(),
                    e);
            repoInfo.setLastCommitId(null);
        }
    }

    @Override
    public Set<RepoInfoVo> parseRepoInfoFromZip(Path sourceZipPath) throws IOException {
        Set<RepoInfoVo> repoInfoSet = new LinkedHashSet<>();
        ZipFile zipFile = new ZipFile(sourceZipPath.toFile());

        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(sourceZipPath.toFile()))) {
            ZipEntry zipEntry;
            while ((zipEntry = zis.getNextEntry()) != null) {
                try {
                    if (isTargetFile(zipEntry)) {
                        String fileContent = IOUtils.toString(zipFile.getInputStream(zipEntry), StandardCharsets.UTF_8);
                        MetaServiceDomain metaService = Mapper.xmlMapper.readValue(fileContent, MetaServiceDomain.class);
                        Set<RepoInfoVo> repoInfos = metaService.getRepoInfo();
                        if (repoInfos == null) {
                            logger.error("{}'s meta info is:{}, can not parse repo info", zipEntry.getName(), fileContent);
                            continue;
                        }
                        repoInfoSet.addAll(repoInfos);
                    }
                } catch (Exception e) {
                    logger.error("", e);
                }
            }
            zis.closeEntry();
        }
        zipFile.close();
        return repoInfoSet;
    }

    private Path createTmpDir() throws IOException {
        return Files.createTempDirectory(SbomRepoConstants.TMP_DIR_PREFIX);
    }

    private boolean isTargetVersion(String filePath) {
        if (ArrayUtils.isEmpty(openEulerNewestVersion) || StringUtils.isEmpty(filePath)) {
            return false;
        }
        for (String targetVersion : openEulerNewestVersion) {
            if (filePath.startsWith(UNZIP_TARGET_FOLDER_PREFIX_PATTERN.formatted(targetVersion))) {
                return true;
            }
        }
        return false;
    }

    private boolean isTargetFile(ZipEntry zipEntry) {
        return (!zipEntry.isDirectory())
                && isTargetVersion(zipEntry.getName())
                && zipEntry.getName().endsWith(OPENEULER_META_FILE_NAME);
    }

}
