package org.opensourceway.sbom.clients.repo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import org.opensourceway.sbom.api.repo.RepoMetaHandler;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoMetaVo;
import org.opensourceway.sbom.model.pojo.vo.repo.ThirdPartyMetaVo;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class RepoMetaHandlerImpl implements RepoMetaHandler {

    private static final Logger logger = LoggerFactory.getLogger(RepoMetaHandlerImpl.class);

    private static final String OPEN_HARMONY_GITEE_ORG = "openharmony";

    private static final Integer DEFAULT_PAGE_SIZE = 100;

    private static final String THIRD_PARTY_REPO_PREFIX = "third_party_";

    private static final String THIRD_PARTY_META_FILE = "README.OpenSource";

    @Value("${openharmony.newest.versions}")
    private String[] openHarmonyNewestVersions;

    @Value("${gitee.domain.url}")
    private String giteeDomainUrl;

    @Autowired
    @Qualifier("giteeApi")
    private VcsApi giteeApi;

    @Override
    public Set<RepoMetaVo> fetchRepoMeta() {
        logger.info("Start to fetch metadata for OpenHarmony repos");

        int page = 1;
        Set<RepoMetaVo> repoMetaVos = new HashSet<>();

        while (true) {
            List<String> repoNames = giteeApi.getOrgRepoNames(OPEN_HARMONY_GITEE_ORG, page, DEFAULT_PAGE_SIZE);
            if (ObjectUtils.isEmpty(repoNames)) {
                logger.info("End to to fetch metadata for OpenHarmony repos");
                return repoMetaVos;
            }

            repoNames.forEach(repo -> {
                giteeApi.getRepoTags(OPEN_HARMONY_GITEE_ORG, repo).stream()
                        .filter(tag -> Arrays.stream(openHarmonyNewestVersions).toList().contains(tag))
                        .forEach(tag -> {
                            if (repo.startsWith(THIRD_PARTY_REPO_PREFIX)) {
                                handleThirdPartyRepo(repo, tag, repoMetaVos);
                            } else {
                                handleNonThirdPartyRepo(repo, tag, repoMetaVos);
                            }
                        });
            });
            page += 1;
        }
    }

    private void handleThirdPartyRepo(String repo, String version, Set<RepoMetaVo> repoMetaVos) {
        try {
            String thirdPartyMetaUrl = MessageFormat.format("{0}/{1}/{2}/raw/{3}/{4}",
                    giteeDomainUrl, OPEN_HARMONY_GITEE_ORG, repo, version, THIRD_PARTY_META_FILE);
            String thirdPartyMeta = giteeApi.getFileContext(thirdPartyMetaUrl);
            List<ThirdPartyMetaVo> vos = Mapper.jsonMapper.readValue(thirdPartyMeta, new TypeReference<>() {});
            RepoMetaVo vo = new RepoMetaVo();
            vo.setRepoName(repo);
            vo.setBranch(version);
            vo.setPackageNames(new String[]{repo.replace(THIRD_PARTY_REPO_PREFIX, "")});
            vo.setDownloadLocation(MessageFormat.format("{0}/{1}/{2}",
                    giteeDomainUrl, OPEN_HARMONY_GITEE_ORG, repo));
            vo.setExtendedAttr(Map.of(repo.replace(THIRD_PARTY_REPO_PREFIX, ""),
                    Map.of("upstream_name", repo.replace(THIRD_PARTY_REPO_PREFIX, ""),
                            "upstream_version", vos.get(0).getVersion().strip(),
                            "upstream_url", vos.get(0).getUpstreamUrl().strip())));
            repoMetaVos.add(vo);
        } catch (JsonProcessingException e) {
            logger.warn("The {} of repo [{}] with version [{}] is invalid", THIRD_PARTY_META_FILE, repo, version);
            handleNonThirdPartyRepo(repo, version, repoMetaVos);
        } catch (RuntimeException e) {
            logger.warn("Unknown exception occurs when fetch repo meta for repo [{}] with version [{}]", repo, version, e);
            handleNonThirdPartyRepo(repo, version, repoMetaVos);
        }
    }

    private void handleNonThirdPartyRepo(String repo, String version, Set<RepoMetaVo> repoMetaVos) {
        RepoMetaVo vo = new RepoMetaVo();
        vo.setRepoName(repo);
        vo.setBranch(version);
        vo.setPackageNames(new String[]{repo});
        vo.setDownloadLocation(MessageFormat.format("{0}/{1}/{2}",
                giteeDomainUrl, OPEN_HARMONY_GITEE_ORG, repo));
        repoMetaVos.add(vo);
    }
}
