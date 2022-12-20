package org.opensourceway.sbom.quartz.jobs;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.repo.RepoService;
import org.opensourceway.sbom.model.pojo.vo.repo.RepoInfoVo;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

import java.util.Set;

public class FetchOpenEulerRepoMetaJob extends QuartzJobBean {

    private static final Logger logger = LoggerFactory.getLogger(FetchOpenEulerRepoMetaJob.class);

    @Autowired
    private RepoService repoService;

    protected void executeInternal(@NotNull JobExecutionContext quartzJobContext) {
        logger.info("start launch fetch-openEuler-repo-meta job");
        long start = System.currentTimeMillis();
        try {
            Set<RepoInfoVo> result = repoService.fetchOpenEulerRepoMeta();
            logger.info("fetch-openEuler-repo-meta result size:{}", result.size());
        } catch (Exception e) {
            logger.error("launch fetch-openEuler-repo-meta job failed", e);
        }
        logger.info("finish launch fetch-openEuler-repo-meta job, coast:{} ms", System.currentTimeMillis() - start);
    }

}
