package org.opensourceway.sbom.service.reader.impl.spdx;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.dao.ChecksumRepository;
import org.opensourceway.sbom.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.dao.PackageRepository;
import org.opensourceway.sbom.dao.PkgVerfCodeExcludedFileRepository;
import org.opensourceway.sbom.dao.PkgVerfCodeRepository;
import org.opensourceway.sbom.dao.SbomCreatorRepository;
import org.opensourceway.sbom.dao.SbomElementRelationshipRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.dao.VulnerabilityRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Checksum;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.ExternalVulRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgVerfCode;
import org.opensourceway.sbom.model.entity.PkgVerfCodeExcludedFile;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomCreator;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.entity.Vulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SpdxReaderTest {

    private static final String PRODUCT_NAME = "SpdxReaderTest";

    @Autowired
    @Qualifier(SbomConstants.SPDX_NAME + SbomConstants.READER_NAME)
    private SpdxReader spdxReader;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private SbomCreatorRepository sbomCreatorRepository;

    @Autowired
    private SbomElementRelationshipRepository sbomElementRelationshipRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private PkgVerfCodeRepository pkgVerfCodeRepository;

    @Autowired
    private PkgVerfCodeExcludedFileRepository pkgVerfCodeExcludedFileRepository;

    @Autowired
    private ChecksumRepository checksumRepository;

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Test
    @Order(1)
    public void setup() {
        cleanDb();
    }

    @Test
    @Order(2)
    public void insertSbom() throws IOException {
        functionBody();
    }

    @Test
    @Order(3)
    public void updateSbom() throws IOException {
        functionBody();
    }

    @Test
    @Order(4)
    public void deleteSbom() {
        Sbom sbom = sbomRepository.findByProductName(PRODUCT_NAME).orElse(null);
        if (sbom == null) {
            return;
        }

        long sbomCreatorSize = sbomCreatorRepository.count();
        long sbomElementRelationshipSize = sbomElementRelationshipRepository.count();
        long packageSize = packageRepository.count();
        long pkgVerfCodeSize = pkgVerfCodeRepository.count();
        long pkgVerfCodeExcludedFileSize = pkgVerfCodeExcludedFileRepository.count();
        long checksumSize = checksumRepository.count();
        long externalPurlRefSize = externalPurlRefRepository.count();
        long vulnerabilitySize = vulnerabilityRepository.count();
        long externalVulRefSize = externalVulRefRepository.count();

        sbomRepository.delete(sbom);

        assertThat(sbomRepository.findByProductName(PRODUCT_NAME).orElse(null)).isNull();
        assertThat(sbomCreatorRepository.count()).isLessThan(sbomCreatorSize);
        assertThat(sbomElementRelationshipRepository.count()).isLessThan(sbomElementRelationshipSize);
        assertThat(packageRepository.count()).isLessThan(packageSize);
        assertThat(pkgVerfCodeRepository.count()).isLessThan(pkgVerfCodeSize);
        assertThat(pkgVerfCodeExcludedFileRepository.count()).isLessThan(pkgVerfCodeExcludedFileSize);
        assertThat(checksumRepository.count()).isLessThan(checksumSize);
        assertThat(externalPurlRefRepository.count()).isLessThan(externalPurlRefSize);
        assertThat(vulnerabilityRepository.count()).isEqualTo(vulnerabilitySize);
        assertThat(externalVulRefRepository.count()).isLessThanOrEqualTo(externalVulRefSize);
    }

    private void cleanDb() {
        Sbom sbom = sbomRepository.findByProductName(PRODUCT_NAME).orElse(null);
        if (sbom == null) {
            return;
        }
        Vulnerability vulnerability = vulnerabilityRepository.findByVulId("cve-2022-00000").orElse(null);

        long sbomCreatorSize = sbomCreatorRepository.count();
        long sbomElementRelationshipSize = sbomElementRelationshipRepository.count();
        long packageSize = packageRepository.count();
        long pkgVerfCodeSize = pkgVerfCodeRepository.count();
        long pkgVerfCodeExcludedFileSize = pkgVerfCodeExcludedFileRepository.count();
        long checksumSize = checksumRepository.count();
        long externalPurlRefSize = externalPurlRefRepository.count();
        long vulnerabilitySize = vulnerabilityRepository.count();
        long externalVulRefSize = externalVulRefRepository.count();

        sbomRepository.delete(sbom);
        if (Objects.nonNull(vulnerability)) {
            vulnerabilityRepository.delete(vulnerability);
        }

        assertThat(sbomRepository.findByProductName(PRODUCT_NAME).orElse(null)).isNull();
        assertThat(sbomCreatorRepository.count()).isLessThan(sbomCreatorSize);
        assertThat(sbomElementRelationshipRepository.count()).isLessThan(sbomElementRelationshipSize);
        assertThat(packageRepository.count()).isLessThan(packageSize);
        assertThat(pkgVerfCodeRepository.count()).isLessThan(pkgVerfCodeSize);
        assertThat(pkgVerfCodeExcludedFileRepository.count()).isLessThan(pkgVerfCodeExcludedFileSize);
        assertThat(checksumRepository.count()).isLessThan(checksumSize);
        assertThat(externalPurlRefRepository.count()).isLessThan(externalPurlRefSize);
        assertThat(vulnerabilityRepository.count()).isLessThanOrEqualTo(vulnerabilitySize);
        assertThat(externalVulRefRepository.count()).isLessThan(externalVulRefSize);
    }

    private void functionBody() throws IOException {
        Vulnerability vulnerability = vulnerabilityRepository
                .findByVulId("cve-2022-00000").orElse(new Vulnerability());
        vulnerability.setVulId("cve-2022-00000");
        vulnerabilityRepository.save(vulnerability);

        spdxReader.read(PRODUCT_NAME, new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME).getFile());

        Sbom sbom = sbomRepository.findByProductName(PRODUCT_NAME).orElse(null);
        assertThat(sbom).isNotNull();
        assertThat(sbom.getProduct().getName()).isEqualTo(PRODUCT_NAME);

        List<SbomCreator> sbomCreators = sbomCreatorRepository.findBySbomId(sbom.getId());
        assertThat(sbomCreators.size()).isEqualTo(1);
        assertThat(sbomCreators.get(0).getSbom().getProduct().getName()).isEqualTo(PRODUCT_NAME);
        assertThat(sbomCreators.get(0).getName()).isEqualTo("Tool: OSS Review Toolkit - e5b343ff71-dirty");

        List<SbomElementRelationship> sbomElementRelationships = sbomElementRelationshipRepository.findBySbomId(sbom.getId());
        assertThat(sbomElementRelationships.size()).isEqualTo(5);

        List<Package> packages = packageRepository.findBySbomId(sbom.getId());
        assertThat(packages.size()).isEqualTo(76);
        packages.forEach(p -> assertThat(p.getSbom().getId()).isEqualTo(sbom.getId()));

        List<Package> specificPackages = packageRepository.findBySbomIdAndSpdxId(sbom.getId(), "SPDXRef-Package-PyPI-asttokens-2.0.5-vcs");
        assertThat(specificPackages.size()).isEqualTo(1);
        assertThat(specificPackages.get(0).getName()).isEqualTo("asttokens");

        List<PkgVerfCode> pkgVerfCodes = pkgVerfCodeRepository.findBySbomId(sbom.getId());
        assertThat(pkgVerfCodes.size()).isEqualTo(1);
        assertThat(pkgVerfCodes.get(0).getValue()).isEqualTo("8aba92182455b539af15d0524fe5baffd3d9248b");

        List<PkgVerfCodeExcludedFile> pkgVerfCodeExcludedFiles = pkgVerfCodeExcludedFileRepository.findBySbomId(sbom.getId());
        assertThat(pkgVerfCodeExcludedFiles.size()).isEqualTo(2);

        List<Checksum> checksums = checksumRepository.findBySbomId(sbom.getId());
        assertThat(checksums.size()).isEqualTo(1);
        assertThat(checksums.get(0).getAlgorithm()).isEqualTo("SHA256");
        assertThat(checksums.get(0).getValue()).isEqualTo("b5dcc8da8a08e73dc2acdf1b1c4b06ca0bab0db5d9da9417c2841c1d6872c126");

        List<ExternalPurlRef> externalPurlRefs = externalPurlRefRepository.findBySbomId(sbom.getId());
        assertThat(externalPurlRefs.size()).isEqualTo(76);

        List<ExternalVulRef> externalVulRefs = externalVulRefRepository.findBySbomId(sbom.getId());
        assertThat(externalVulRefs.size()).isEqualTo(0);
    }
}