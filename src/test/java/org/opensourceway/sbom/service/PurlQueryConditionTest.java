package org.opensourceway.sbom.service;

import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.util.Pair;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class PurlQueryConditionTest {

    @Test
    public void mavenOnlyNameTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("maven", "", "zookeeper", ""), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("maven");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("zookeeper");
        assertThat(result.get("name").getSecond()).isFalse();

        assertThat(result.containsValue("namespace")).isFalse();
        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void mavenNameAndNamespaceTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("maven", "org.apache.zookeeper", "zookeeper", ""), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("maven");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("namespace").getFirst()).isEqualTo("org.apache.zookeeper");
        assertThat(result.get("namespace").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("zookeeper");
        assertThat(result.get("name").getSecond()).isFalse();

        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void mavenNameAndNamespaceAndStartVersionTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("maven", "org.apache.zookeeper", "zookeeper", ""), "3.4.6" , null);

        assertThat(result.get("type").getFirst()).isEqualTo("maven");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("namespace").getFirst()).isEqualTo("org.apache.zookeeper");
        assertThat(result.get("namespace").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("zookeeper");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void mavenGavTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("maven", "org.apache.zookeeper", "zookeeper", "3.4.6"), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("maven");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("namespace").getFirst()).isEqualTo("org.apache.zookeeper");
        assertThat(result.get("namespace").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("zookeeper");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.get("version").getFirst()).isEqualTo("3.4.6");
        assertThat(result.get("version").getSecond()).isTrue();
    }

    @Test
    public void notSupportTypeTest() {
        Map<String, Pair<String, Boolean>> result = null;
        try {
            result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                    new PackageUrlVo("pip", "org.apache.zookeeper", "zookeeper", "3.4.6"), null , null);
        } catch (RuntimeException e) {
            assertThat(e.getMessage()).isEqualTo("purl query condition not support type: pip");
        }
        assertThat(result).isNull();
    }

    @Test
    public void pypiOnlyNameTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("pypi", "", "numpy", ""), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("pypi");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("numpy");
        assertThat(result.get("name").getSecond()).isFalse();

        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void pypiNameAndStartVersionTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("pypi", "", "numpy", ""), "1.21.0" , null);

        assertThat(result.get("type").getFirst()).isEqualTo("pypi");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("numpy");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void pypiNameAndVersionTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("pypi", "", "numpy", "5.9.1"), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("pypi");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("numpy");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.get("version").getFirst()).isEqualTo("5.9.1");
        assertThat(result.get("version").getSecond()).isTrue();
    }

    @Test
    public void rpmOnlyNameTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("rpm", "", "openssl", ""), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("rpm");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("openssl");
        assertThat(result.get("name").getSecond()).isFalse();

        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void rpmNameAndStartVersionTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("rpm", "", "openssl", ""), "1.1.1" , null);

        assertThat(result.get("type").getFirst()).isEqualTo("rpm");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("openssl");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.containsValue("version")).isFalse();
    }

    @Test
    public void rpmNameAndVersionTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("rpm", "", "openssl", "1.2.3"), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("rpm");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("openssl");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.get("version").getFirst()).isEqualTo("1.2.3");
        assertThat(result.get("version").getSecond()).isFalse();
    }

    @Test
    public void mavenCheckSumTest1() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("maven", "checksum", "b314c7ebb7d599944981908b7f3ed33a30e78f3a", "1.0.0"), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("maven");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("namespace").getFirst()).isEqualTo("checksum");
        assertThat(result.get("namespace").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("b314c7ebb7d599944981908b7f3ed33a30e78f3a");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.get("version").getFirst()).isEqualTo("1.0.0");
        assertThat(result.get("version").getSecond()).isTrue();
    }

    @Test
    public void mavenCheckSumTest2() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("maven", "sha1", "b314c7ebb7d599944981908b7f3ed33a30e78f3a", "1.0.0"), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("maven");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("namespace").getFirst()).isEqualTo("sha1");
        assertThat(result.get("namespace").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("b314c7ebb7d599944981908b7f3ed33a30e78f3a");
        assertThat(result.get("name").getSecond()).isTrue();

        assertThat(result.get("version").getFirst()).isEqualTo("1.0.0");
        assertThat(result.get("version").getSecond()).isTrue();
    }

    @Test
    public void genericOnlyNameTest() {
        Map<String, Pair<String, Boolean>> result = ExternalPurlRefCondition.generatePurlQueryConditionMap(
                new PackageUrlVo("generic", "", "libedit", ""), null , null);

        assertThat(result.get("type").getFirst()).isEqualTo("generic");
        assertThat(result.get("type").getSecond()).isTrue();

        assertThat(result.get("name").getFirst()).isEqualTo("libedit");
        assertThat(result.get("name").getSecond()).isFalse();

        assertThat(result.containsKey("version")).isFalse();
    }

}
