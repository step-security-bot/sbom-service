package org.opensourceway.sbom.dao;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spec.ExternalPurlRefCondition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ExternalPurlRefRepositoryTest {

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Test
    public void queryPackageRefByRelationTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .version("3.1.2-3.oe2203")
                .build();

        Pageable pageable = PageRequest.of(0, 15);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);

        assertThat(pageResult.isEmpty()).isFalse();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(3);
        assertThat(pageResult.getTotalElements()).isEqualTo(3);
        assertThat(pageResult.getTotalPages()).isEqualTo(1);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(0);

        List<ExternalPurlRef> result = pageResult.getContent();
        assertThat(result.get(0).getPurl().getType()).isEqualTo("rpm");
        assertThat(result.get(0).getPurl().getNamespace()).isNull();
        assertThat(result.get(0).getPurl().getName()).isEqualTo("hadoop-3.1-common");
        assertThat(result.get(0).getPurl().getVersion()).isEqualTo("3.1.4-4.oe2203");

        assertThat(result.get(1).getPurl().getName()).isEqualTo("spark");
        assertThat(result.get(2).getPurl().getName()).isEqualTo("storm");
    }

    @Test
    public void queryPackageRefByRelationTest1() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("zookeeper")
                .version("3.6.2-2.4.oe2203")
                .build();

        Pageable pageable = PageRequest.of(0, 15);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);

        assertThat(pageResult.isEmpty()).isFalse();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(1);
        assertThat(pageResult.getTotalElements()).isEqualTo(1);
        assertThat(pageResult.getTotalPages()).isEqualTo(1);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(0);

        List<ExternalPurlRef> result = pageResult.getContent();
        assertThat(result.get(0).getPurl().getType()).isEqualTo("rpm");
        assertThat(result.get(0).getPurl().getNamespace()).isNull();
        assertThat(result.get(0).getPurl().getName()).isEqualTo("hive");
        assertThat(result.get(0).getPurl().getVersion()).isEqualTo("3.1.2-3.oe2203");
    }

    @Test
    public void queryPackageRefByRelationSecondPageTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .version("3.1.2-3.oe2203")
                .build();

        Pageable pageable = PageRequest.of(1, 15);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);
        assertThat(pageResult.isEmpty()).isTrue();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(0);
        assertThat(pageResult.getTotalElements()).isEqualTo(3);
        assertThat(pageResult.getTotalPages()).isEqualTo(1);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(1);
    }

    @Test
    public void queryPackageRefByRelationLimit1Test() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .version("3.1.2-3.oe2203")
                .build();

        Pageable pageable = PageRequest.of(0, 1);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);

        assertThat(pageResult.isEmpty()).isFalse();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(1);
        assertThat(pageResult.getTotalElements()).isEqualTo(3);
        assertThat(pageResult.getTotalPages()).isEqualTo(3);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(0);

        List<ExternalPurlRef> result = pageResult.getContent();
        assertThat(result).isNotEmpty();
        assertThat(result.size()).isEqualTo(1);

        assertThat(result.get(0).getPurl().getType()).isEqualTo("rpm");
        assertThat(result.get(0).getPurl().getNamespace()).isNull();
        assertThat(result.get(0).getPurl().getName()).isEqualTo("hadoop-3.1-common");
        assertThat(result.get(0).getPurl().getVersion()).isEqualTo("3.1.4-4.oe2203");
    }

    @Test
    public void queryPackageRefByRelationEmptyVersionTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .version("")
                .build();

        Pageable pageable = PageRequest.of(0, 15);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);

        assertThat(pageResult.isEmpty()).isFalse();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(3);
        assertThat(pageResult.getTotalElements()).isEqualTo(3);
        assertThat(pageResult.getTotalPages()).isEqualTo(1);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(0);

        List<ExternalPurlRef> result = pageResult.getContent();
        assertThat(result).isNotEmpty();
        assertThat(result.size()).isEqualTo(3);

        assertThat(result.get(0).getPurl().getType()).isEqualTo("rpm");
        assertThat(result.get(0).getPurl().getNamespace()).isNull();
        assertThat(result.get(0).getPurl().getName()).isEqualTo("hadoop-3.1-common");
        assertThat(result.get(0).getPurl().getVersion()).isEqualTo("3.1.4-4.oe2203");

        assertThat(result.get(1).getPurl().getName()).isEqualTo("spark");
        assertThat(result.get(2).getPurl().getName()).isEqualTo("storm");
    }

    @Test
    public void queryPackageRefByRelationNoVersionTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .build();

        Pageable pageable = PageRequest.of(0, 15);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);

        assertThat(pageResult.isEmpty()).isFalse();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(3);
        assertThat(pageResult.getTotalElements()).isEqualTo(3);
        assertThat(pageResult.getTotalPages()).isEqualTo(1);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(0);

        List<ExternalPurlRef> result = pageResult.getContent();
        assertThat(result).isNotEmpty();
        assertThat(result.size()).isEqualTo(3);

        assertThat(result.get(0).getPurl().getType()).isEqualTo("rpm");
        assertThat(result.get(0).getPurl().getNamespace()).isNull();
        assertThat(result.get(0).getPurl().getName()).isEqualTo("hadoop-3.1-common");
        assertThat(result.get(0).getPurl().getVersion()).isEqualTo("3.1.4-4.oe2203");

        assertThat(result.get(1).getPurl().getName()).isEqualTo("spark");
        assertThat(result.get(2).getPurl().getName()).isEqualTo("storm");
    }

    @Test
    public void queryPackageRefByRelationErrorVersionTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .version("1111")
                .build();

        Pageable pageable = PageRequest.of(0, 15);
        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, pageable);

        assertThat(pageResult.isEmpty()).isTrue();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(0);
        assertThat(pageResult.getTotalElements()).isEqualTo(0);
        assertThat(pageResult.getTotalPages()).isEqualTo(0);
        assertThat(pageResult.getPageable().getPageNumber()).isEqualTo(0);

        List<ExternalPurlRef> result = pageResult.getContent();
        assertThat(result).isEmpty();
    }

    @Test
    public void queryPackageRefByRelationWithoutPageTest() {
        ExternalPurlRefCondition condition = ExternalPurlRefCondition.Builder.newBuilder()
                .productName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME)
                .sbomId(sbomRepository.findByProductName(TestConstants.SAMPLE_REPODATA_PRODUCT_NAME).orElseThrow().getId())
                .binaryType(ReferenceCategory.RELATIONSHIP_MANAGER.name())
                .type("rpm")
                .namespace("")
                .name("hive")
                .version("")
                .build();

        Page<ExternalPurlRef> pageResult = externalPurlRefRepository.queryPackageRefByRelation(condition, null);

        assertThat(pageResult.isEmpty()).isFalse();
        assertThat(pageResult.getNumberOfElements()).isEqualTo(3);
        assertThat(pageResult.getTotalElements()).isEqualTo(3);
        assertThat(pageResult.getTotalPages()).isEqualTo(1);
        assertThat(pageResult.getPageable().isUnpaged()).isTrue();

        List<ExternalPurlRef> result = pageResult.getContent();

        assertThat(result).isNotEmpty();
        assertThat(result.size()).isEqualTo(3);

        assertThat(result.get(0).getPurl().getType()).isEqualTo("rpm");
        assertThat(result.get(0).getPurl().getNamespace()).isNull();
        assertThat(result.get(0).getPurl().getName()).isEqualTo("hadoop-3.1-common");
        assertThat(result.get(0).getPurl().getVersion()).isEqualTo("3.1.4-4.oe2203");

        assertThat(result.get(1).getPurl().getName()).isEqualTo("spark");
        assertThat(result.get(2).getPurl().getName()).isEqualTo("storm");
    }

}
