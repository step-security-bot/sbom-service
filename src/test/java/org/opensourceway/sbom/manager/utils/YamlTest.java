package org.opensourceway.sbom.manager.utils;

import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.pojo.UpstreamInfoVo;
import org.opensourceway.sbom.utils.YamlUtil;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class YamlTest {

    @Test
    public void parse() {
        String yamlContent =
                "git_url: https://gitee.com/openeuler/oemaker\n" +
                        "version_control: gitee\n" +
                        "src_repo: openeuler/oemaker\n" +
                        "tag_prefix: \"^v\"\n" +
                        "seperator: \".\"";
        UpstreamInfoVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

        assertThat(upstreamInfo.getGitUrl()).isEqualTo("https://gitee.com/openeuler/oemaker");
        assertThat(upstreamInfo.getVersionControl()).isEqualTo("gitee");
        assertThat(upstreamInfo.getSrcRepo()).isEqualTo("openeuler/oemaker");
        assertThat(upstreamInfo.getTagPrefix()).isEqualTo("^v");
        assertThat(upstreamInfo.getSeperator()).isEqualTo(".");
    }

    @Test
    public void parseWithoutGitUrl() {
        String yamlContent =
                "version_control: github\n" +
                        "src_repo: jemalloc/jemalloc\n" +
                        "tag_prefix: ^\n" +
                        "seperator: .";
        UpstreamInfoVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

        assertThat(upstreamInfo.getGitUrl()).isNull();
        assertThat(upstreamInfo.getVersionControl()).isEqualTo("github");
        assertThat(upstreamInfo.getSrcRepo()).isEqualTo("jemalloc/jemalloc");
        assertThat(upstreamInfo.getTagPrefix()).isEqualTo("^");
        assertThat(upstreamInfo.getSeperator()).isEqualTo(".");
    }

    @Test
    public void parseEmpty() {
        String yamlContent = "";
        UpstreamInfoVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

        assertThat(upstreamInfo).isNull();
    }

}
