package org.opensourceway.sbom.service;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.SbomManagerApplication;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.service.checksum.impl.ChecksumServiceImpl;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
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
        product.setAttribute(Map.of("productType", "testProduct", "arg", "8"));
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

        Package pkg1 = new Package();
        pkg1.setName("test");
        pkg1.setSbom(sbom);
        List<ExternalPurlRef> externalPurlRefList1 = new ArrayList<>();
        ExternalPurlRef externalPurlRef4 = new ExternalPurlRef();
        externalPurlRef4.setType(SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);
        externalPurlRef4.setCategory(ReferenceCategory.EXTERNAL_MANAGER.name());
        PackageUrlVo packageUrlVo4 = new PackageUrlVo("pkg", "maven", "sha1",
                "5af35056b4d257e4b64b9e8069c0746e8b08629f", "1.0.0", null, null);
        externalPurlRef4.setPurl(packageUrlVo4);
        externalPurlRef4.setPkg(pkg1);
        externalPurlRefList1.add(externalPurlRef4);
        pkg1.setExternalPurlRefs(externalPurlRefList1);

        sbom.setPackages(List.of(pkg, pkg1));
        productRepository.save(product);

    }

    @Test
    @Order(1)
    public void getExternalPurlRef() {
        initChecksumSbom();
        Sbom sbom = sbomRepository.findByProductName(TestConstants.PUBLISH_TEST_CHECKSUM_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        assertThat(sbom.getPackages().size()).isEqualTo(2);
        assertThat(sbom.getPackages().stream().map(Package::getExternalPurlRefs).mapToLong(List::size).sum()).isEqualTo(4);
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

        Package pkg1 = packageRepository.findBySbomIdAndSpdxId(sbom.getId(), null).get(1);
        List<List<ExternalPurlRef>> externalPurlRefList1 = checksumServiceImpl.extractGAVByChecksumRef(pkg1.getId(),
                ReferenceCategory.EXTERNAL_MANAGER.name(),
                SbomConstants.ExternalPurlRef_TYPE_CHECKSUM);
        Assertions.assertThat(externalPurlRefList1.get(0).size()).isEqualTo(1);
        Assertions.assertThat(externalPurlRefList1.get(1).size()).isEqualTo(0);
        checksumServiceImpl.persistExternalGAVRef(externalPurlRefList1);
        assertThat(pkg1.getExternalPurlRefs().size()).isEqualTo(1);
        assertThat(pkg1.getExternalPurlRefs().get(0).getPurl().getNamespace()).isEqualTo("log4j");
        assertThat(pkg1.getExternalPurlRefs().get(0).getPurl().getName()).isEqualTo("log4j");
        assertThat(pkg1.getExternalPurlRefs().get(0).getPurl().getVersion()).isEqualTo("1.2.17");
    }
}
