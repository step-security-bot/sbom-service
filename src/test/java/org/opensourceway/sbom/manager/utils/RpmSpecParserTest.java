package org.opensourceway.sbom.manager.utils;

import com.google.common.collect.Multimap;
import org.assertj.core.api.Assertions;
import org.computer.whunter.rpm.parser.RpmSpecParser;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.util.Properties;

public class RpmSpecParserTest {

    @Test
    public void testParserForProperties() {
        try {
            RpmSpecParser parser = RpmSpecParser.createParser("src/test/resources/specs/389-ds-base.spec");
            Assertions.assertThat(parser).isNotNull();

            Multimap<String, String> multimap = parser.parse();
            Properties properties = parser.toProperties(multimap);

            System.out.printf("RPM name: %s, version: %s-%s %n", multimap.get("name"), multimap.get("version"), multimap.get("release"));
            System.out.printf("RPM name: %s, version: %s-%s %n", properties.getProperty("name"), properties.getProperty("version"), properties.getProperty("release"));

            checkMultimapResults(multimap);
            checkPropertiesResults(properties);
        } catch (FileNotFoundException e) {
            Assertions.fail(e.toString());
        }
    }

    private void checkPropertiesResults(Properties properties) {
        Assertions.assertThat(properties).isNotNull();
        Assertions.assertThat(properties.size() > 0).isTrue();
        Assertions.assertThat(properties.getProperty("name")).isEqualTo("389-ds-base");
        Assertions.assertThat(properties.getProperty("buildarch")).isEqualTo("noarch");
        Assertions.assertThat(properties.getProperty("license")).isEqualTo("GPLv3+");
        Assertions.assertThat(properties.containsKey("prefix")).isFalse();
        Assertions.assertThat(properties.containsKey("buildroot")).isFalse();
        Assertions.assertThat(properties.getProperty("packager")).isEqualTo("opensourceways");
        Assertions.assertThat(properties.getProperty("version")).isEqualTo("1.4.3.20");
        Assertions.assertThat(properties.getProperty("summary")).isEqualTo("Documentation for 389 Directory Server");
        Assertions.assertThat(properties.getProperty("provides")).isEqualTo("svrcore-devel = 4.1.4");
        Assertions.assertThat(properties.getProperty("release")).isEqualTo("1");
        Assertions.assertThat(properties.getProperty("autoreqprov")).isEqualTo("no");
        Assertions.assertThat(properties.getProperty("group")).isEqualTo("Applications/Test");
        Assertions.assertThat(properties.getProperty("source0")).isEqualTo("https://releases.pagure.org/389-ds-base/389-ds-base-1.4.3.20.tar.bz2");
        Assertions.assertThat(properties.getProperty("source3")).isEqualTo("https://github.com/jemalloc/jemalloc/releases/download/5.2.1/jemalloc-5.2.1.tar.bz2");
        Assertions.assertThat(properties.getProperty("patch0")).isEqualTo("CVE-2021-3652.patch");
        Assertions.assertThat(properties.getProperty("patch2")).isEqualTo("Fix-attributeError-type-object-build_manpages.patch");
        Assertions.assertThat(properties.getProperty("requires")).isEqualTo("389-ds-base = 1.4.3.20-1");
        Assertions.assertThat(properties.getProperty("url")).isEqualTo("https://www.port389.org");
        Assertions.assertThat(properties.getProperty("who")).isEqualTo("opensourceway");
        Assertions.assertThat(properties.getProperty("vendor")).isEqualTo("opensourceway himself");
    }

    private void checkMultimapResults(Multimap<String, String> multimap) {
        Assertions.assertThat(multimap).isNotNull();
        Assertions.assertThat(multimap.size() > 0).isTrue();
        // single value
        Assertions.assertThat(multimap.get("name").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("license").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("packager").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("version").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("url").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("who").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("vendor").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("release").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("autoreqprov").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("group").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("source0").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("source3").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("patch0").size()).isEqualTo(1);
        Assertions.assertThat(multimap.get("patch2").size()).isEqualTo(1);

        // non value
        Assertions.assertThat(multimap.get("prefix").size()).isEqualTo(0);
        Assertions.assertThat(multimap.get("buildroot").size()).isEqualTo(0);

        // multi values
        Assertions.assertThat(multimap.get("buildarch").size()).isEqualTo(2);
        Assertions.assertThat(multimap.get("buildarch").contains("noarch")).isTrue();
        Assertions.assertThat(multimap.get("summary").size()).isEqualTo(7);
        Assertions.assertThat(multimap.get("summary").contains("Base 389 Directory Server")).isTrue();
        Assertions.assertThat(multimap.get("summary").contains("Development libraries for 389 Directory Server")).isTrue();
        Assertions.assertThat(multimap.get("summary").contains("SNMP Agent for 389 Directory Server")).isTrue();
        Assertions.assertThat(multimap.get("provides").size()).isEqualTo(2);
        Assertions.assertThat(multimap.get("provides").contains("389-ds-base-libs = 1.4.3.20-1 svrcore = 4.1.4 ldif2ldbm >= 0")).isTrue();
        Assertions.assertThat(multimap.get("provides").contains("svrcore-devel = 4.1.4")).isTrue();
        Assertions.assertThat(multimap.get("requires").size()).isEqualTo(20);
        Assertions.assertThat(multimap.get("requires").contains("389-ds-base-libs = 1.4.3.20-1")).isTrue();
        Assertions.assertThat(multimap.get("requires").contains("python%{python3_pkgversion}-lib389 = 1.4.3.20-1")).isTrue();
        Assertions.assertThat(multimap.get("requires").contains("389-ds-base-libs = 1.4.3.20-1 pkgconfig nspr-devel nss-devel >= 3.34")).isTrue();

        Assertions.assertThat(multimap.get("%package").size()).isEqualTo(6);
        Assertions.assertThat(multimap.get("%package").contains("devel")).isTrue();
        Assertions.assertThat(multimap.get("%package").contains("help")).isTrue();
        Assertions.assertThat(multimap.get("%package").contains("legacy-tools")).isTrue();
        Assertions.assertThat(multimap.get("%package").contains("snmp")).isTrue();
        Assertions.assertThat(multimap.get("%package").contains("-n cockpit-389-ds")).isTrue();
    }

}
