package org.opensourceway.sbom.manager.service;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.SbomApplicationContextHolder;
import org.opensourceway.sbom.manager.SbomManagerApplication;
import org.opensourceway.sbom.manager.TestConstants;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.service.checksum.impl.ChecksumServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ChecksumToGAVTest {
    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ChecksumServiceImpl checksumServiceImpl;

    @Test
    @Order(0)
    public void deleteChecksumSbom() {
        productRepository.findByName(TestConstants.PUBLISH_TEST_CHECKSUM_NAME).ifPresent(product -> productRepository.delete(product));
        Product product = productRepository.findByName(TestConstants.PUBLISH_TEST_CHECKSUM_NAME).orElse(null);
        assertThat(product).isNull();
    }


    public void initChecksumSbom() {
        Product product = new Product();
        product.setName(TestConstants.PUBLISH_TEST_CHECKSUM_NAME);
        product.setAttribute(Map.of("arg", "8"));
        Sbom sbom = new Sbom(product);
        sbom.setName("checksumTest");
        product.setSbom(sbom);
        Package pkg = new Package();
        pkg.setName("hive");
        pkg.setSbom(sbom);
        List<ExternalPurlRef> externalPurlRefList = new ArrayList<>();
        ExternalPurlRef externalPurlRef1 = new ExternalPurlRef();
        externalPurlRef1.setType(SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);
        externalPurlRef1.setCategory(ReferenceCategory.EXTERNAL_MANAGER.name());
        PackageUrlVo packageUrlVo1 = new PackageUrlVo("pkg", "maven", "sha1",
                "9a782bd40f6a5d8537db98439d69cf562b8071a9", "1.0.0", null, null);
        externalPurlRef1.setPurl(packageUrlVo1);
        externalPurlRef1.setPkg(pkg);
        ExternalPurlRef externalPurlRef2 = new ExternalPurlRef();
        externalPurlRef2.setType(SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);
        externalPurlRef2.setCategory(ReferenceCategory.EXTERNAL_MANAGER.name());
        PackageUrlVo packageUrlVo2 = new PackageUrlVo("pkg", "maven", "sha1",
                "4387a31bd61d51b7de9bce354c89dc5c5b8c1768", "1.0.0", null, null);
        externalPurlRef2.setPurl(packageUrlVo2);
        externalPurlRef2.setPkg(pkg);
        ExternalPurlRef externalPurlRef3 = new ExternalPurlRef();
        externalPurlRef3.setType(SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);
        externalPurlRef3.setCategory(ReferenceCategory.EXTERNAL_MANAGER.name());
        PackageUrlVo packageUrlVo3 = new PackageUrlVo("pkg", "maven", "sha1",
                "xxx", "1.0.0", null, null);
        externalPurlRef3.setPurl(packageUrlVo3);
        externalPurlRef3.setPkg(pkg);
        externalPurlRefList.add(externalPurlRef1);
        externalPurlRefList.add(externalPurlRef2);
        externalPurlRefList.add(externalPurlRef3);
        pkg.setExternalPurlRefs(externalPurlRefList);
        sbom.setPackages(List.of(pkg));
        productRepository.save(product);

    }

    @Test
    @Order(1)
    public void getExternalPurlRef() {
        initChecksumSbom();
        Sbom sbom = sbomRepository.findByProductName(TestConstants.PUBLISH_TEST_CHECKSUM_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        assertThat(sbom.getPackages().size()).isEqualTo(1);
        assertThat(sbom.getPackages().get(0).getExternalPurlRefs().size()).isEqualTo(3);
    }

    @Test
    @Order(2)
    public void queryGAVInfoByBinaryChecksum() {
        Sbom sbom = sbomRepository.findByProductName(TestConstants.PUBLISH_TEST_CHECKSUM_NAME).orElse(null);
        assert sbom != null;
        Package pkg = packageRepository.findBySbomIdAndSpdxId(sbom.getId(), null).get(0);

        List<List<ExternalPurlRef>> externalPurlRefList = checksumServiceImpl.extractGAVByChecksumRef(pkg.getId(),
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);
        Assertions.assertThat(externalPurlRefList.get(0).size()).isEqualTo(1);
        Assertions.assertThat(externalPurlRefList.get(1).size()).isEqualTo(2);
        checksumServiceImpl.persistExternalGAVRef(externalPurlRefList);
        assertThat(pkg.getExternalPurlRefs().size()).isEqualTo(1);
        assertThat(pkg.getExternalPurlRefs().get(0).getPurl().getNamespace()).isEqualTo("org.apache.hbase");
        assertThat(pkg.getExternalPurlRefs().get(0).getPurl().getName()).isEqualTo("hbase-common");
        assertThat(pkg.getExternalPurlRefs().get(0).getPurl().getVersion()).isEqualTo("2.0.0-alpha4");
    }
}
