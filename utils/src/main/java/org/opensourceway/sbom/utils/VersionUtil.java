package org.opensourceway.sbom.utils;

import java.lang.module.ModuleDescriptor.Version;
import java.util.Objects;

public class VersionUtil {
    public static Version parse(String v) {
        try {
            return Version.parse(v);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static Boolean greaterThanOrEqualTo(String v, String another) {
        var version = parse(v);
        var anotherVersion = parse(another);

        if (Objects.isNull(version) || Objects.isNull(anotherVersion)) {
            return v.compareTo(another) >= 0;
        }

        return version.compareTo(anotherVersion) >= 0;
    }

    public static Boolean lessThanOrEqualTo(String v, String another) {
        var version = parse(v);
        var anotherVersion = parse(another);

        if (Objects.isNull(version) || Objects.isNull(anotherVersion)) {
            return v.compareTo(another) <= 0;
        }

        return version.compareTo(anotherVersion) <= 0;
    }

    public static Boolean inRange(String v, String start, String end) {
        var version = parse(v);
        var startVersion = parse(start);
        var endVersion = parse(end);

        if (Objects.isNull(version) || Objects.isNull(startVersion) || Objects.isNull(endVersion)) {
            return v.compareTo(start) >= 0 && v.compareTo(end) <= 0;
        }

        return version.compareTo(startVersion) >= 0 && version.compareTo(endVersion) <= 0;
    }
}
