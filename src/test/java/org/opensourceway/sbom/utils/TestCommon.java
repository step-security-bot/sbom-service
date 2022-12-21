package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.enums.SbomContentType;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.opensourceway.sbom.model.spdx.SpdxDocument;
import org.opensourceway.sbom.model.spdx.SpdxPackage;
import org.opensourceway.sbom.model.spdx.SpdxRelationship;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@Service
public class TestCommon {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private RawSbomRepository rawSbomRepository;

    public static void assertSpdxDocument(SpdxDocument spdxDocument) {
        assertThat(spdxDocument.getSpdxVersion()).isEqualTo("SPDX-2.2");
        assertThat(spdxDocument.getName()).isEqualTo("Unnamed document");
        assertThat(spdxDocument.getDataLicense()).isEqualTo("CC0-1.0");
        assertThat(spdxDocument.getCreationInfo().creators().size()).isEqualTo(1);
        assertThat(spdxDocument.getCreationInfo().creators().get(0)).isEqualTo("Tool: OSS Review Toolkit - e5b343ff71-dirty");
        assertThat(spdxDocument.getCreationInfo().licenseListVersion()).isEqualTo("3.16");
        assertThat(spdxDocument.getCreationInfo().created()).isEqualTo("2022-06-27T08:05:09Z");
        assertThat(spdxDocument.getDocumentNamespace()).isEqualTo("spdx://57eaa8d8-9572-44ff-ace4-d4ac38292265");
        assertThat(spdxDocument.getPackages().size()).isEqualTo(78);
        assertThat(spdxDocument.getRelationships().size()).isEqualTo(36);

        Optional<SpdxPackage> pkgOptional = spdxDocument.getPackages().stream()
                .filter(tempPkg -> StringUtils.endsWithIgnoreCase("SPDXRef-Package-github-abseil-cpp-20210324.2", tempPkg.getSpdxId()))
                .findFirst();
        assertThat(pkgOptional.isPresent()).isTrue();
        SpdxPackage pkg = pkgOptional.get();
        assertThat(pkg.getHomepage()).isEqualTo("https://abseil.io");
        assertThat(pkg.getLicenseDeclared()).isEqualTo("Apache-2.0");
        assertThat(pkg.getName()).isEqualTo("abseil-cpp");
        assertThat(pkg.getVersionInfo()).isEqualTo("20210324.2");

        SpdxRelationship relationship = spdxDocument.getRelationships().get(0);
        assertThat(relationship.spdxElementId()).isEqualTo("SPDXRef-Package-PyPI-asttokens-2.0.5");
        assertThat(relationship.relationshipType().name()).isEqualTo(RelationshipType.DEPENDS_ON.name());
        assertThat(relationship.relatedSpdxElement()).isEqualTo("SPDXRef-Package-PyPI-six-1.16.0");
    }

    public void cleanPublishRawSbomData(String productName) {
        Optional<Product> productOptional = productRepository.findByName(productName);
        if (productOptional.isEmpty()) {
            return;
        }

        RawSbom condition = new RawSbom();
        condition.setProduct(productOptional.get());
        condition.setValueType(SbomContentType.SPDX_2_2_JSON_SBOM.getType());

        RawSbom existRawSbom = rawSbomRepository.queryRawSbom(condition);
        if (existRawSbom != null) {
            rawSbomRepository.delete(existRawSbom);
        }
    }
}
