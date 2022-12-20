package org.opensourceway.sbom.utils;

import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class OpenEulerAdvisorParserTest {

    @Autowired
    private OpenEulerAdvisorParser advisorParser;

    @Test
    public void emptyContentTest() {
        String advisorContent = "";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isNull();
    }

    @Test
    public void nullContentTest() {
        String result = advisorParser.parseUpstreamLocation(null);

        Assertions.assertThat(result).isNull();
    }

    @Test
    public void noVersionControlTest() {
        String advisorContent = "src_repo: 389ds/389-ds-base\n" +
                "tag_prefix: 389-ds-base-\n" +
                "seperator: .";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isNull();
    }

    @Test
    public void emptyVersionControlTest() {
        String advisorContent = "version_control: \n" +
                "src_repo: 389ds/389-ds-base\n" +
                "tag_prefix: 389-ds-base-\n" +
                "seperator: .";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isNull();
    }

    @Test
    public void errorVersionControlTest() {
        String advisorContent = "version_control: xxx\n" +
                "src_repo: 389ds/389-ds-base\n" +
                "tag_prefix: 389-ds-base-\n" +
                "seperator: .";

        RuntimeException exception = null;
        try {
            advisorParser.parseUpstreamLocation(advisorContent);
        } catch (RuntimeException e) {
            exception = e;
        }

        Assertions.assertThat(exception).isNotNull();
        Assertions.assertThat(StringUtils.startsWith(exception.getMessage(), "OpenEulerAdvisorParser not support vcs control:xxx, advisorContent:version_control: xxx")).isTrue();
    }


    @Test
    public void NAControlTest() {
        String advisorContent = "version_control: NA\n" +
                "src_repo: NA\n" +
                "tag_prefix: NA\n" +
                "separator: NA";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isNull();
    }

    @Test
    public void githubSrcRepoTest() {
        String advisorContent = "version_control: github\n" +
                "src_repo: 389ds/389-ds-base\n" +
                "tag_prefix: 389-ds-base-\n" +
                "seperator: .";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://github.com/389ds/389-ds-base");
    }

    @Test
    public void githubGitUrlTest() {
        String advisorContent = "version_control: github\n" +
                "src_repo: alsa-project/alsa-firmware\n" +
                "tag_prefix: \"^v\"\n" +
                "separator: \".\"\n" +
                "git_url: https://github.com/alsa-project/alsa-firmware.git";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://github.com/alsa-project/alsa-firmware.git");
    }

    @Test
    public void githubUrlTest() {
        String advisorContent = "version_control: github\n" +
                "src_repo: alsa-project/alsa-firmware\n" +
                "tag_prefix: \"^v\"\n" +
                "separator: \".\"\n" +
                "url: https://github.com/FasterXML/aalto-xml.git\n" +
                "git_url: https://github.com/alsa-project/alsa-firmware.git";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://github.com/FasterXML/aalto-xml.git");
    }

    @Test
    public void githubNoUrlTest() {
        String advisorContent = "version_control: github\n" +
                "tag_prefix: \"^v\"\n" +
                "separator: \".\"\n";

        RuntimeException exception = null;
        try {
            advisorParser.parseUpstreamLocation(advisorContent);
        } catch (RuntimeException e) {
            exception = e;
        }

        Assertions.assertThat(exception).isNotNull();
        Assertions.assertThat(StringUtils.startsWith(exception.getMessage(), "OpenEulerAdvisorParser not support, advisorContent:version_control: github")).isTrue();

    }

    @Test
    public void giteeTest1() {
        String advisorContent = "git_url: https://gitee.com/openeuler/oemaker\n" +
                "version_control: gitee\n" +
                "src_repo: openeuler/oemaker\n" +
                "tag_prefix: \"^v\"\n" +
                "seperator: \".\"";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://gitee.com/openeuler/oemaker");
    }

    @Test
    public void giteeTest2() {
        String advisorContent = "version_control: gitee\n" +
                "src_repo: openeuler/authz\n" +
                "tag_prefix: \"^v\"\n" +
                "separator: \".\"";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://gitee.com/openeuler/authz");
    }

    @Test
    public void gitlabGnomeTest() {
        String advisorContent = "version_control: gitlab.gnome\n" +
                "src_repo: adwaita-icon-theme\n" +
                "tag_prefix: GNOME_ICON_THEME_\n" +
                "separator: _\n" +
                "git_url: https://gitlab.gnome.org/GNOME/adwaita-icon-theme.git\n" +
                "git_tag:";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://gitlab.gnome.org/GNOME/adwaita-icon-theme.git");
    }

    @Test
    public void gnuFtpTest1() {
        String advisorContent = "version_control: gnu-ftp\n" +
                "src_repo: bc\n" +
                "tag_pattern: bc-(.*).tar.gz(.sig)?\n" +
                "separator: \".\"";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://ftp.gnu.org/gnu/bc");
    }

    @Test
    public void gnuFtpTest2() {
        String advisorContent = "version_control: gnu-ftp\n" +
                "src_repo: barcode\n" +
                "tag_pattern: barcode-(.*).tar.gz(sig)? \n" +
                "separator: \".\"\n" +
                "url: https://ftp.gnu.org/gnu/barcode/";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://ftp.gnu.org/gnu/barcode/");
    }

    @Test
    public void sourceforgeTest() {
        String advisorContent = "version_control: sourceforge\n" +
                "src_repo: https://sourceforge.net/projects/aa-project/files/aa-lib\n" +
                "tag_prefix: \n" +
                "separator: ";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://sourceforge.net/projects/aa-project/files/aa-lib");
    }

    @Test
    public void svnTest() {
        String advisorContent = "version_control: svn\n" +
                "src_repo: https://svn.apache.org/repos/asf/apr/apr-util\n" +
                "tag_prefix: \"^\"\n" +
                "separator: \".\"";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://svn.apache.org/repos/asf/apr/apr-util");
    }

    @Test
    public void gitTest1() {
        String advisorContent = "version_control: git\n" +
                "src_repo: http://git.alsa-project.org/http/alsa-plugins.git\n" +
                "tag_prefix: \"^v\"\n" +
                "separator: \".\"\n" +
                "url: http://git.alsa-project.org/http/alsa-plugins.git\n" +
                "git_url: http://git.alsa-project.org/http/alsa-plugins.git";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("http://git.alsa-project.org/http/alsa-plugins.git");
    }

    @Test
    public void gitTest2() {
        String advisorContent = "version_control: git\n" +
                "src_repo: https://gitlab.freedesktop.org/realmd/adcli.git\n" +
                "tag_prefix: \"^\"\n" +
                "separator: \".\"\n" +
                "git_url: https://gitlab.freedesktop.org/realmd/adcli.git\n" +
                "git_tag:";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://gitlab.freedesktop.org/realmd/adcli.git");
    }

    @Test
    public void gitTest3() {
        String advisorContent = "version_control: git\n" +
                "src_repo: https://pagure.io/bind-dyndb-ldap.git\n" +
                "tag_prefix: \"^v\"\n" +
                "separator: \".\"";
        String result = advisorParser.parseUpstreamLocation(advisorContent);

        Assertions.assertThat(result).isEqualTo("https://pagure.io/bind-dyndb-ldap.git");
    }

}
