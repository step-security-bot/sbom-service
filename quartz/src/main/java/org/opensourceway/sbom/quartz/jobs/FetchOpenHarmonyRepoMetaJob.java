package org.opensourceway.sbom.quartz.jobs;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.repo.RepoService;
import org.opensourceway.sbom.model.entity.RepoMeta;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

import java.util.List;

public class FetchOpenHarmonyRepoMetaJob extends QuartzJobBean {

    private static final Logger logger = LoggerFactory.getLogger(FetchOpenHarmonyRepoMetaJob.class);

    @Autowired
    private RepoService repoService;

    protected void executeInternal(@NotNull JobExecutionContext quartzJobContext) {
        logger.info("start launch fetch-OpenHarmony-repo-meta job");
        long start = System.currentTimeMillis();
        try {
            List<RepoMeta> result = repoService.fetchOpenHarmonyRepoMeta();
            logger.info("fetch-OpenHarmony-repo-meta result size:{}", result.size());
        } catch (Exception e) {
            logger.error("launch fetch-OpenHarmony-repo-meta job failed", e);
        }
        logger.info("finish launch fetch-OpenHarmony-repo-meta job, coast:{} ms", System.currentTimeMillis() - start);
    }
}
