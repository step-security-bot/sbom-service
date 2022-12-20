package org.opensourceway.sbom.utils;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class RegexUtilTests {
    @Test
    public void parsePurlFromRepoUrl() {
        Map.of(
                "https://gitee.com/mindspore/akg/archive/refs/tags/v1.7.0.tar.gz", "pkg:gitee/mindspore/akg@v1.7.0",
                "https://gitee.com/mindspore/graphengine/archive/refs/tags/v1.0.0.tar.gz", "pkg:gitee/mindspore/graphengine@v1.0.0",
                "https://github.com/abseil/abseil-cpp/archive/20210324.2.tar.gz", "pkg:github/abseil/abseil-cpp@20210324.2",
                "https://github.com/c-ares/c-ares/releases/download/cares-1_15_0/c-ares-1.15.0.tar.gz", "pkg:github/c-ares/c-ares@cares-1_15_0",
                "https://github.com/google/flatbuffers/archive/v2.0.0.tar.gz", "pkg:github/google/flatbuffers@v2.0.0",
                "https://github.com/google/glog/archive/v0.4.0.tar.gz", "pkg:github/google/glog@v0.4.0",
                "https://github.com/google/re2/archive/2019-12-01.tar.gz", "pkg:github/google/re2@2019-12-01",
                "https://github.com/google/sentencepiece/archive/v0.1.92.tar.gz", "pkg:github/google/sentencepiece@v0.1.92",
                "https://github.com/grpc/grpc/archive/v1.36.1.tar.gz", "pkg:github/grpc/grpc@v1.36.1",
                "https://github.com/leethomason/tinyxml2/archive/8.0.0.tar.gz", "pkg:github/leethomason/tinyxml2@8.0.0"
        ).forEach((url, purl) -> assertThat(Objects.requireNonNull(RegexUtil.parsePurlFromRepoUrl(url)).canonicalize()).isEqualTo(purl));


        Map.of(
                "https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz", "pkg:github/libevent/libevent@release-2.1.12-stable",
                "https://github.com/libjpeg-turbo/libjpeg-turbo/archive/2.0.4.tar.gz", "pkg:github/libjpeg-turbo/libjpeg-turbo@2.0.4",
                "https://github.com/madler/zlib/archive/v1.2.11.tar.gz", "pkg:github/madler/zlib@v1.2.11",
                "https://github.com/nlohmann/json/releases/download/v3.7.3/include.zip", "pkg:github/nlohmann/json@v3.7.3",
                "https://github.com/oneapi-src/oneDNN/archive/v2.2.tar.gz", "pkg:github/oneapi-src/onednn@v2.2",
                "https://github.com/opencv/opencv/archive/4.5.2.tar.gz", "pkg:github/opencv/opencv@4.5.2",
                "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1k.tar.gz", "pkg:github/openssl/openssl@OpenSSL_1_1_1k",
                "https://github.com/protocolbuffers/protobuf/archive/v3.13.0.tar.gz", "pkg:github/protocolbuffers/protobuf@v3.13.0",
                "https://github.com/pybind/pybind11/archive/v2.4.3.tar.gz", "pkg:github/pybind/pybind11@v2.4.3",
                "https://github.com/sqlite/sqlite/archive/version-3.36.0.tar.gz", "pkg:github/sqlite/sqlite@version-3.36.0"
        ).forEach((url, purl) -> assertThat(Objects.requireNonNull(RegexUtil.parsePurlFromRepoUrl(url)).canonicalize()).isEqualTo(purl));

        Map.of(
                "https://github.com/unicode-org/icu/archive/release-69-1.tar.gz", "pkg:github/unicode-org/icu@release-69-1",
                "https://github.com/yanyiwu/cppjieba/archive/v5.0.3.tar.gz", "pkg:github/yanyiwu/cppjieba@v5.0.3",
                "https://gitlab.com/libeigen/eigen/-/archive/3.3.9/eigen-3.3.9.tar.gz", "pkg:gitlab/libeigen/eigen@3.3.9"

        ).forEach((url, purl) -> assertThat(Objects.requireNonNull(RegexUtil.parsePurlFromRepoUrl(url)).canonicalize()).isEqualTo(purl));
    }
}
