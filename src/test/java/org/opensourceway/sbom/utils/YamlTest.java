package org.opensourceway.sbom.utils;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.model.pojo.vo.repo.OpenEulerAdvisorVo;
import org.yaml.snakeyaml.scanner.ScannerException;

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
        OpenEulerAdvisorVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

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
        OpenEulerAdvisorVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

        assertThat(upstreamInfo.getGitUrl()).isNull();
        assertThat(upstreamInfo.getVersionControl()).isEqualTo("github");
        assertThat(upstreamInfo.getSrcRepo()).isEqualTo("jemalloc/jemalloc");
        assertThat(upstreamInfo.getTagPrefix()).isEqualTo("^");
        assertThat(upstreamInfo.getSeperator()).isEqualTo(".");
    }

    @Test
    public void parseExtendField() {
        String yamlContent =
                "version_control: github\n" +
                        "src_repo: jemalloc/jemalloc\n" +
                        "tag_prefix: ^\n" +
                        "seperator: .\n" +
                        "tag_xxxx: GNOME_ICON_THEME_";
        OpenEulerAdvisorVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

        assertThat(upstreamInfo.getGitUrl()).isNull();
        assertThat(upstreamInfo.getVersionControl()).isEqualTo("github");
        assertThat(upstreamInfo.getSrcRepo()).isEqualTo("jemalloc/jemalloc");
        assertThat(upstreamInfo.getTagPrefix()).isEqualTo("^");
        assertThat(upstreamInfo.getSeperator()).isEqualTo(".");
    }

    @Test
    public void parseEmpty() {
        String yamlContent = "";
        OpenEulerAdvisorVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

        assertThat(upstreamInfo).isNull();
    }

    @Test
    public void parseErrorYaml1() {
        ScannerException expectedException = null;
        try {
            String yamlContent =
                    "version_control: github\n" +
                            "src_repo: docbook/xslt10-stylesheets\n" +
                            "tag_prefix: ^snapshot/ \n" +
                            "seperator: - ";
            OpenEulerAdvisorVo upstreamInfo = YamlUtil.parseFromStr(yamlContent);

            assertThat(upstreamInfo.getGitUrl()).isNull();
            assertThat(upstreamInfo.getVersionControl()).isEqualTo("github");
            assertThat(upstreamInfo.getSrcRepo()).isEqualTo("jemalloc/jemalloc");
            assertThat(upstreamInfo.getTagPrefix()).isEqualTo("^");
            assertThat(upstreamInfo.getSeperator()).isEqualTo(".");
        } catch (ScannerException e) {
            expectedException = e;
        } catch (Exception e) {
            Assertions.fail(e.toString());
        }

        Assertions.assertThat(expectedException).isNotNull();
        Assertions.assertThat(expectedException.getMessage().indexOf("sequence entries are not allowed here")).isGreaterThanOrEqualTo(0);
    }

}
