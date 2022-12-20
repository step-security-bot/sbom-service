package org.opensourceway.sbom.utils;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.api.vcs.VcsApi;
import org.opensourceway.sbom.model.pojo.response.vcs.gitlab.GitlabRepoInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class GitlabTest {

    private static final String GET_REPO_ORG = "libeigen";

    private static final String GET_REPO_NAME = "eigen";

    @Autowired
    @Qualifier("gitlabApi")
    private VcsApi gitlabApi;

    @Test
    @Disabled
    public void getRepoInfoTest() {
        GitlabRepoInfo.RepoInfo repoInfo = (GitlabRepoInfo.RepoInfo) gitlabApi.getRepoInfo(GET_REPO_ORG, GET_REPO_NAME).block();
        Assertions.assertThat(repoInfo).isNotNull();
        Assertions.assertThat(repoInfo.owner()).isNull();
        Assertions.assertThat(repoInfo.homepage()).isEqualTo("https://gitlab.com/libeigen/eigen");
        Assertions.assertThat(repoInfo.repoUrl()).isEqualTo("https://gitlab.com/libeigen/eigen.git");
        Assertions.assertThat(repoInfo.license().name()).isEqualTo("Other");
    }

}
