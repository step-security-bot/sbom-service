package org.openeuler.sbom.manager.service.reader.impl.spdx;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.openeuler.sbom.manager.constant.SbomConstants;
import org.openeuler.sbom.manager.dao.ProductRepository;
import org.openeuler.sbom.manager.dao.SbomRepository;
import org.openeuler.sbom.manager.dao.VulnerabilityRepository;
import org.openeuler.sbom.manager.model.Checksum;
import org.openeuler.sbom.manager.model.ExternalPurlRef;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.PkgVerfCode;
import org.openeuler.sbom.manager.model.PkgVerfCodeExcludedFile;
import org.openeuler.sbom.manager.model.Sbom;
import org.openeuler.sbom.manager.model.SbomCreator;
import org.openeuler.sbom.manager.model.SbomElementRelationship;
import org.openeuler.sbom.manager.model.spdx.ReferenceType;
import org.openeuler.sbom.manager.model.spdx.SpdxDocument;
import org.openeuler.sbom.manager.model.spdx.SpdxPackage;
import org.openeuler.sbom.manager.service.reader.SbomReader;
import org.openeuler.sbom.manager.service.vul.VulService;
import org.openeuler.sbom.manager.utils.PurlUtil;
import org.openeuler.sbom.manager.utils.SbomFormat;
import org.openeuler.sbom.manager.utils.SbomMapperUtil;
import org.openeuler.sbom.manager.utils.SbomSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.openeuler.sbom.manager.utils.SbomMapperUtil.fileToExt;

@Service(value = SbomConstants.SPDX_NAME + SbomConstants.READER_NAME)
@Transactional(rollbackFor = Exception.class)
public class SpdxReader implements SbomReader {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    private final List<VulService> vulServices;

    @Autowired
    public SpdxReader(List<VulService> vulServices) {
        this.vulServices = vulServices;
    }

    @Override
    public void read(String productName, File file) throws IOException {
        SbomFormat format = fileToExt(file.getName());
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] fileContent = fileInputStream.readAllBytes();
        fileInputStream.close();

        read(productName, format, fileContent);
    }

    @Override
    public void read(String productName, SbomFormat format, byte[] fileContent) throws IOException {
        SpdxDocument document = SbomMapperUtil.readDocument(format, SbomSpecification.SPDX_2_2.getDocumentClass(), fileContent);
        Sbom sbom = persistSbom(productName, document);
        vulServices.forEach(vulService -> vulService.persistExternalVulRefForSbom(sbom, true));
    }

    private Sbom persistSbom(String productName, SpdxDocument document) {
        Sbom sbom = sbomRepository.findByProductName(productName)
                .orElse(new Sbom(productRepository.findByName(productName)
                        .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)))));
        sbom.setCreated(document.getCreationInfo().created().toString());
        sbom.setDataLicense(document.getDataLicense());
        sbom.setLicenseListVersion(document.getCreationInfo().licenseListVersion());
        sbom.setName(document.getName());
        sbom.setNamespace(document.getDocumentNamespace());
        List<SbomCreator> sbomCreators = persistSbomCreators(document, sbom);
        sbom.setSbomCreators(sbomCreators);
        List<SbomElementRelationship> sbomElementRelationships = persistSbomElementRelationship(document, sbom);
        sbom.setSbomElementRelationships(sbomElementRelationships);
        List<Package> packages = persistPackages(document, sbom);
        sbom.setPackages(packages);
        return sbomRepository.saveAndFlush(sbom);
    }

    private List<SbomCreator> persistSbomCreators(SpdxDocument document, Sbom sbom) {
        if (Objects.isNull(document.getCreationInfo().creators())) {
            return new ArrayList<>();
        }

        Map<String, SbomCreator> existSbomCreators = Optional
                .ofNullable(sbom.getSbomCreators())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(SbomCreator::getName, Function.identity()));
        List<SbomCreator> sbomCreators = new ArrayList<>();
        document.getCreationInfo().creators().forEach(it -> {
            SbomCreator sbomCreator = existSbomCreators.getOrDefault(it, new SbomCreator());
            sbomCreator.setName(it);
            sbomCreator.setSbom(sbom);
            sbomCreators.add(sbomCreator);
        });
        return sbomCreators;
    }

    private List<SbomElementRelationship> persistSbomElementRelationship(SpdxDocument document, Sbom sbom) {
        if (Objects.isNull(document.getRelationships())) {
            return new ArrayList<>();
        }

        Map<Triple<String, String, String>, SbomElementRelationship> existSbomElementRelationships = Optional
                .ofNullable(sbom.getSbomElementRelationships())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Triple.of(
                        it.getElementId(), it.getRelatedElementId(), it.getRelationshipType()), Function.identity()));

        List<SbomElementRelationship> sbomElementRelationships = new ArrayList<>();
        document.getRelationships().forEach(it -> {
            SbomElementRelationship sbomElementRelationship = existSbomElementRelationships.getOrDefault(
                    Triple.of(it.spdxElementId(), it.relatedSpdxElement(), it.relationshipType().name()), new SbomElementRelationship());
            sbomElementRelationship.setElementId(it.spdxElementId());
            sbomElementRelationship.setRelatedElementId(it.relatedSpdxElement());
            sbomElementRelationship.setRelationshipType(it.relationshipType().name());
            sbomElementRelationship.setComment(it.comment());
            sbomElementRelationship.setSbom(sbom);
            sbomElementRelationships.add(sbomElementRelationship);
        });
        return sbomElementRelationships;
    }

    private List<Package> persistPackages(SpdxDocument document, Sbom sbom) {
        if (Objects.isNull(document.getPackages())) {
            return new ArrayList<>();
        }

        List<Package> packages = new ArrayList<>();
        Map<Triple<String, String, String>, Package> existPackages = Optional.ofNullable(sbom.getPackages())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Triple.of(it.getSpdxId(), it.getName(), it.getVersion()), Function.identity()));
        document.getPackages().forEach(it -> {
            Package pkg = existPackages.getOrDefault(Triple.of(it.getSpdxId(), it.getName(), it.getVersionInfo()), new Package());
            pkg.setSpdxId(it.getSpdxId());
            pkg.setName(it.getName());
            pkg.setVersion(it.getVersionInfo());
            pkg.setCopyright(it.getCopyrightText());
            pkg.setDescription(it.getDescription());
            pkg.setDownloadLocation(it.getDownloadLocation());
            pkg.setFilesAnalyzed(it.getFilesAnalyzed());
            pkg.setHomepage(it.getHomepage());
            pkg.setLicenseConcluded(it.getLicenseConcluded());
            pkg.setLicenseDeclared(it.getLicenseDeclared());
            pkg.setSourceInfo(it.getSourceInfo());
            pkg.setSummary(it.getSummary());
            pkg.setSupplier(it.getSupplier());
            pkg.setSbom(sbom);

            PkgVerfCode pkgVerfCode = persistPkgVerfCode(it, pkg);
            pkg.setPkgVerfCode(pkgVerfCode);
            List<Checksum> checksums = persistChecksums(it, pkg);
            pkg.setChecksums(checksums);
            List<ExternalPurlRef> externalRefs = persistExternalRefs(it, pkg);
            pkg.setExternalPurlRefs(externalRefs);
            pkg.setExternalVulRefs(pkg.getExternalVulRefs());

            packages.add(pkg);
        });
        return packages;
    }

    private PkgVerfCode persistPkgVerfCode(SpdxPackage spdxPackage, Package pkg) {
        if (Objects.isNull(spdxPackage.getPackageVerificationCode())) {
            return null;
        }

        PkgVerfCode pkgVerfCode = Optional.ofNullable(pkg.getPkgVerfCode()).orElse(new PkgVerfCode());
        pkgVerfCode.setPkg(pkg);
        pkgVerfCode.setValue(spdxPackage.getPackageVerificationCode().packageVerificationCodeValue());

        List<PkgVerfCodeExcludedFile> files = persistPkgVerfCodeExcludedFiles(spdxPackage, pkgVerfCode);
        pkgVerfCode.setPkgVerfCodeExcludedFiles(files);
        return pkgVerfCode;
    }

    private List<PkgVerfCodeExcludedFile> persistPkgVerfCodeExcludedFiles(SpdxPackage spdxPackage, PkgVerfCode pkgVerfCode) {
        if (Objects.isNull(spdxPackage.getPackageVerificationCode()) ||
                Objects.isNull(spdxPackage.getPackageVerificationCode().packageVerificationCodeExcludedFiles())) {
            return new ArrayList<>();
        }

        List<PkgVerfCodeExcludedFile> pkgVerfCodeExcludedFiles = new ArrayList<>();
        Map<String, PkgVerfCodeExcludedFile> existPkgVerfCodeExcludedFiles = Optional
                .ofNullable(pkgVerfCode.getPkgVerfCodeExcludedFiles())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(PkgVerfCodeExcludedFile::getFile, Function.identity()));

        spdxPackage.getPackageVerificationCode().packageVerificationCodeExcludedFiles().forEach(f -> {
            PkgVerfCodeExcludedFile pkgVerfCodeExcludedFile = existPkgVerfCodeExcludedFiles.getOrDefault(f, new PkgVerfCodeExcludedFile());
            pkgVerfCodeExcludedFile.setFile(f);
            pkgVerfCodeExcludedFile.setPkgVerfCode(pkgVerfCode);
            pkgVerfCodeExcludedFiles.add(pkgVerfCodeExcludedFile);

        });
        return pkgVerfCodeExcludedFiles;
    }

    private List<Checksum> persistChecksums(SpdxPackage spdxPackage, Package pkg) {
        if (Objects.isNull(spdxPackage.getChecksums())) {
            return new ArrayList<>();
        }

        List<Checksum> checksums = new ArrayList<>();
        Map<Pair<String, String>, Checksum> existChecksums = Optional.ofNullable(pkg.getChecksums())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Pair.of(it.getAlgorithm(), it.getValue()), Function.identity()));
        spdxPackage.getChecksums().forEach(it -> {
            Checksum checksum = existChecksums.getOrDefault(Pair.of(it.algorithm().name(), it.checksumValue()), new Checksum());
            checksum.setAlgorithm(it.algorithm().toString());
            checksum.setValue(it.checksumValue());
            checksum.setPkg(pkg);
            checksums.add(checksum);
        });
        return checksums;
    }

    private List<ExternalPurlRef> persistExternalRefs(SpdxPackage spdxPackage, Package pkg) {
        if (Objects.isNull(spdxPackage.getExternalRefs())) {
            return new ArrayList<>();
        }

        List<ExternalPurlRef> externalPurlRefs = new ArrayList<>();
        Map<Triple<String, String, String>, ExternalPurlRef> existExternalPurlRefs = Optional
                .ofNullable(pkg.getExternalPurlRefs())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Triple.of(it.getCategory(), it.getType(),
                        PurlUtil.PackageUrlVoToPackageURL(it.getPurl()).canonicalize()), Function.identity()));
        spdxPackage.getExternalRefs().forEach(it -> {
            if (it.referenceType() == ReferenceType.PURL) {
                ExternalPurlRef externalPurlRef = existExternalPurlRefs.getOrDefault(
                        Triple.of(it.referenceCategory().name(), it.referenceType().getType(),
                                PurlUtil.canonicalizePurl(it.referenceLocator())), new ExternalPurlRef());
                externalPurlRef.setCategory(it.referenceCategory().name());
                externalPurlRef.setType(it.referenceType().getType());
                externalPurlRef.setComment(it.comment());
                externalPurlRef.setPurl(PurlUtil.strToPackageUrlVo(it.referenceLocator()));
                externalPurlRef.setPkg(pkg);
                externalPurlRefs.add(externalPurlRef);
            }
        });
        return externalPurlRefs;
    }
}
