package org.opensourceway.sbom.openeuler.obs.impl;

import com.google.common.collect.Multimap;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.computer.whunter.rpm.parser.RpmSpecParser;
import org.opensourceway.sbom.clients.vcs.VcsApi;
import org.opensourceway.sbom.clients.vcs.gitee.model.GiteeFileInfo;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.openeuler.obs.RepoMetaParser;
import org.opensourceway.sbom.openeuler.obs.SbomRepoConstants;
import org.opensourceway.sbom.openeuler.obs.vo.MetaServiceDomain;
import org.opensourceway.sbom.openeuler.obs.vo.RepoInfoVo;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;


@Service
public class RepoMetaParserImpl implements RepoMetaParser {

    private static final Logger logger = LoggerFactory.getLogger(RepoMetaParserImpl.class);

    public static final String ZIP_ROOT_FOLDER_NAME = "obs_meta-master";

    public static final String UNZIP_TARGET_FOLDER_PREFIX_PATTERN = ZIP_ROOT_FOLDER_NAME
            .concat(SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR)
            .concat("%s")
            .concat(SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR);

    public static final String OPENEULER_META_FILE_NAME = "_service";

    @Value("${openeuler.newest.versions}")
    private String[] openEulerNewestVersion;

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

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

    /**
     * fetch repo's download url of spec file and yaml files
     */
    @Override
    public void fetchRepoBuildFileInfo(Set<RepoInfoVo> repoInfoSet) {
        int counter = 0;

        Iterator<RepoInfoVo> repoInfoIt = repoInfoSet.iterator();
        while (repoInfoIt.hasNext()) {
            RepoInfoVo repoInfo = repoInfoIt.next();
            if (counter++ % 20 == 0) {
                logger.info("fetchRepoBuildFileInfo times:{}, repo name:{}", counter, repoInfo.getRepoName());
            }
            try {
                List<GiteeFileInfo> specFileList = giteeApi.findRepoFiles(SbomRepoConstants.OPENEULER_REPO_ORG,
                        repoInfo.getRepoName(),
                        repoInfo.getBranch(),
                        SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR,
                        SbomRepoConstants.SPEC_FILE_NAME_REGEX);
                if (CollectionUtils.isEmpty(specFileList)) {
                    repoInfoIt.remove();
                    continue;
                }
                specFileList.stream()
                        .findFirst()
                        .ifPresent(specFile -> repoInfo.setSpecDownloadUrl(specFile.downloadUrl()));

                giteeApi.findRepoFiles(SbomRepoConstants.OPENEULER_REPO_ORG,
                                repoInfo.getRepoName(),
                                repoInfo.getBranch(),
                                SbomConstants.LINUX_FILE_SYSTEM_SEPARATOR,
                                SbomRepoConstants.YAML_FILE_NAME_REGEX)
                        .forEach(yamlFile -> repoInfo.addUpstreamDownloadUrl(yamlFile.downloadUrl()));

                repoInfo.setDownloadLocation(SbomRepoConstants.OPENEULER_REPO_SOURCE_URL_PATTERN
                        .formatted(giteeApi.getDefaultBaseUrl(),
                                SbomRepoConstants.OPENEULER_REPO_ORG,
                                repoInfo.getRepoName(),
                                repoInfo.getBranch()));
            } catch (WebClientResponseException.NotFound e) {
                logger.warn("repo name:{}, repo branch:{} can't be found in Gitee, and remove it",
                        repoInfo.getRepoName(),
                        repoInfo.getBranch());
                repoInfoIt.remove();
            } catch (Exception e) {
                logger.error("repo name:{}, repo branch:{} fetch repo build file info failed, and remove it, failed info:",
                        repoInfo.getRepoName(),
                        repoInfo.getBranch(),
                        e);
                repoInfoIt.remove();
            }
        }
    }

    @Override
    public void fetchRepoPackageAndPatchInfo(Set<RepoInfoVo> repoInfoSet) {
        long counter = 0;
        for (RepoInfoVo repoInfo : repoInfoSet) {
            try {
                if (counter++ % 20 == 0) {
                    logger.info("fetchRepoPackageAndPatchInfo times:{}, repo name:{}", counter, repoInfo.getRepoName());
                }
                String specContent = giteeApi.getFileContext(repoInfo.getSpecDownloadUrl());
                if (StringUtils.isEmpty(specContent)) {
                    logger.error("repo name:{}, spec url:{}, is empty",
                            repoInfo.getRepoName(),
                            repoInfo.getSpecDownloadUrl());
                    continue;
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
            }
        }
    }

    @Override
    public void fetchRepoUpstreamInfo(Set<RepoInfoVo> repoInfoSet) {
        // TODO completed fo openEuler upstream info
        throw new RuntimeException("not implemented");
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
