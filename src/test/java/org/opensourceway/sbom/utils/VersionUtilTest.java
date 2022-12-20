package org.opensourceway.sbom.utils;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class VersionUtilTest {
    @Test
    public void parse() {
        assertThat(VersionUtil.parse("")).isNull();
        assertThat(VersionUtil.parse(null)).isNull();
        assertThat(VersionUtil.parse("1_0_0")).isNotNull();
        assertThat(VersionUtil.parse("2019-12-01")).isNotNull();
        assertThat(VersionUtil.parse("2.1.12-stable")).isNotNull();
        assertThat(VersionUtil.parse("1.4.36-1.oe2203")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0")).isNotNull();
        assertThat(VersionUtil.parse("1")).isNotNull();
        assertThat(VersionUtil.parse("1.0")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0.0")).isNotNull();
        assertThat(VersionUtil.parse("1.0.1")).isNotNull();
        assertThat(VersionUtil.parse("1.0.2")).isNotNull();
        assertThat(VersionUtil.parse("1.0.11")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0-alpha")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0-alpha.1")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0-alpha.1.a-bc")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0-beta")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0-beta.2")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0-rc.1")).isNotNull();
        assertThat(VersionUtil.parse("1.0.0+build-12345")).isNotNull();
    }

    @Test
    public void sort() {
        var sorted = Stream.of(
                "1.0.0",
                "1",
                "1.0",
                "1.0.0.0",
                "1.0.1",
                "1.0.2",
                "1.0.11",
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.1.a-bc",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-rc.1",
                "1.0.0-rc.1+build-12345",
                "1.0.0+build-12345",
                "1.1.0",
                "1.2.0",
                "1.11.0",
                "2.0.0",
                "10.0.0"
        ).map(v -> {
            var version = VersionUtil.parse(v); return Objects.isNull(version) ? "" : version;
        }).sorted().map(Object::toString).toList();

        List<String> expected = List.of(
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.1.a-bc",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0+build-12345",
                "1.0.0-rc.1",
                "1.0.0-rc.1+build-12345",
                "1.0.0",
                "1",
                "1.0",
                "1.0.0.0",
                "1.0.1",
                "1.0.2",
                "1.0.11",
                "1.1.0",
                "1.2.0",
                "1.11.0",
                "2.0.0",
                "10.0.0"
        );

        assertThat(sorted).isEqualTo(expected);
    }

    @Test
    public void greaterThanOrEqualTo() {
        assertThat(VersionUtil.greaterThanOrEqualTo("1.2.0", "1.1.11")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("1.2.0", "1.2.0")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("1.2.0", "1.2.1")).isFalse();
        assertThat(VersionUtil.greaterThanOrEqualTo("2020-11-01", "2019-12-09")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("2019-12-10", "2019-12-09")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("1.4.36-1.oe2203", "1.4.35-1.oe2203")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("1.4.36-1.oe2203", "1.3.37-1.oe2203")).isTrue();

        assertThat(VersionUtil.greaterThanOrEqualTo("v1.2.0", "v1.1.11")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("v1.2.0", "v1.2.0")).isTrue();
        assertThat(VersionUtil.greaterThanOrEqualTo("v1.11.0", "v1.2.0")).isFalse();
    }

    @Test
    public void lessThanOrEqualTo() {
        assertThat(VersionUtil.lessThanOrEqualTo("1.1.11", "1.2.0")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("1.2.0", "1.2.0")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("1.2.1", "1.2.0")).isFalse();
        assertThat(VersionUtil.lessThanOrEqualTo("2019-12-09", "2020-11-01")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("2019-12-09", "2019-12-10")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("1.4.35-1.oe2203", "1.4.36-1.oe2203")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("1.3.37-1.oe2203", "1.4.36-1.oe2203")).isTrue();

        assertThat(VersionUtil.lessThanOrEqualTo("v1.1.11", "v1.2.0")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("v1.2.0", "v1.2.0")).isTrue();
        assertThat(VersionUtil.lessThanOrEqualTo("v1.2.0", "v1.11.0")).isFalse();
    }

    @Test
    public void inRange() {
        assertThat(VersionUtil.inRange("1.1.11", "1.1.0", "1.2.0")).isTrue();
        assertThat(VersionUtil.inRange("1.2.0", "1.1.11", "1.2.1")).isTrue();
        assertThat(VersionUtil.inRange("1.2.1", "1.2.2", "1.2.10")).isFalse();
        assertThat(VersionUtil.inRange("1.2.1", "1.11.0", "1.20.10")).isFalse();
        assertThat(VersionUtil.inRange("2019-12-09", "2019-12-09", "2020-11-01")).isTrue();
        assertThat(VersionUtil.inRange("2019-12-09", "2019-01-10", "2019-12-08")).isFalse();
        assertThat(VersionUtil.inRange("1.4.35-1.oe2203", "1.4.34-1.oe2203", "1.4.36-1.oe2203")).isTrue();
        assertThat(VersionUtil.inRange("1.4.35-1.oe2203", "1.4.35-2.oe2203", "1.4.36-1.oe2203")).isFalse();

        assertThat(VersionUtil.inRange("v1.1.11", "v1.1.0", "v1.2.0")).isTrue();
        // String comparing will result in an unexpected 'true'
        assertThat(VersionUtil.inRange("v1.2.1", "v1.11.0", "v1.20.10")).isTrue();
    }
}
