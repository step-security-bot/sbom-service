package org.opensourceway.sbom.service.reader.impl.spdx;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.opensourceway.sbom.api.reader.SbomReader;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Checksum;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.PkgVerfCode;
import org.opensourceway.sbom.model.entity.PkgVerfCodeExcludedFile;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomCreator;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.enums.SbomSpecification;
import org.opensourceway.sbom.model.sbom.SbomDocument;
import org.opensourceway.sbom.model.spdx.ReferenceType;
import org.opensourceway.sbom.model.spdx.SpdxDocument;
import org.opensourceway.sbom.model.spdx.SpdxPackage;
import org.opensourceway.sbom.utils.PurlUtil;
import org.opensourceway.sbom.utils.SbomMapperUtil;
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

@Service(value = SbomConstants.SPDX_NAME + SbomConstants.READER_NAME)
@Transactional(rollbackFor = Exception.class)
public class SpdxReader implements SbomReader {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Override
    public void read(String productName, File file) throws IOException {
        SbomFormat format = SbomMapperUtil.fileToExt(file.getName());
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] fileContent = fileInputStream.readAllBytes();
        fileInputStream.close();

        read(productName, format, fileContent);
    }

    @Override
    public void read(String productName, SbomFormat format, byte[] fileContent) throws IOException {
        SpdxDocument document = SbomMapperUtil.readDocument(format, SbomSpecification.SPDX_2_2.getDocumentClass(), fileContent);
        persistSbom(productName, document);
    }

    @Override
    public SbomDocument readToDocument(String productName, SbomFormat format, byte[] fileContent) throws IOException {
        return SbomMapperUtil.readDocument(format, SbomSpecification.SPDX_2_2.getDocumentClass(), fileContent);
    }

    @Override
    public Sbom persistSbom(String productName, SbomDocument sbomDocument) {
        SpdxDocument spdxDocument = (SpdxDocument) sbomDocument;

        // FIXME: 此处的sbom不用再查了，PersistSbomMetadataStep中已经做了删除
        Sbom sbom = sbomRepository.findByProductName(productName)
                .orElse(new Sbom(productRepository.findByName(productName)
                        .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)))));
        sbom.setCreated(spdxDocument.getCreationInfo().created());
        sbom.setDataLicense(spdxDocument.getDataLicense());
        sbom.setLicenseListVersion(spdxDocument.getCreationInfo().licenseListVersion());
        sbom.setName(spdxDocument.getName());
        sbom.setNamespace(spdxDocument.getDocumentNamespace());
        List<SbomCreator> sbomCreators = persistSbomCreators(spdxDocument, sbom);
        sbom.setSbomCreators(sbomCreators);
        List<SbomElementRelationship> sbomElementRelationships = persistSbomElementRelationship(spdxDocument, sbom);
        sbom.setSbomElementRelationships(sbomElementRelationships);
        List<Package> packages = persistPackages(spdxDocument, sbom);
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
            Triple<String, String, String> key = Triple.of(it.spdxElementId(), it.relatedSpdxElement(), it.relationshipType().name());
            SbomElementRelationship sbomElementRelationship;
            if (existSbomElementRelationships.containsKey(key)) {
                sbomElementRelationship = existSbomElementRelationships.get(key);
            } else {
                sbomElementRelationship = new SbomElementRelationship();
                existSbomElementRelationships.put(key, sbomElementRelationship);
            }

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

    private List<ExternalPurlRef> persistExternalRefs(SpdxPackage spdxPackage, Package existPkg) {
        if (Objects.isNull(spdxPackage.getExternalRefs())) {
            return new ArrayList<>();
        }

        List<ExternalPurlRef> externalPurlRefs = new ArrayList<>();
        Map<Triple<String, String, String>, ExternalPurlRef> existExternalPurlRefs = Optional
                .ofNullable(existPkg.getExternalPurlRefs())
                .orElse(new ArrayList<>())
                .stream()
                .collect(Collectors.toMap(it -> Triple.of(it.getCategory(), it.getType(),
                        PurlUtil.canonicalizePurl(it.getPurl())), Function.identity()));
        spdxPackage.getExternalRefs().forEach(it -> {
            if (List.of(ReferenceType.PURL, ReferenceType.CHECKSUM).contains(it.referenceType())) {
                ExternalPurlRef externalPurlRef = existExternalPurlRefs.getOrDefault(
                        Triple.of(it.referenceCategory().name(), it.referenceType().getType(),
                                PurlUtil.canonicalizePurl(it.referenceLocator())), new ExternalPurlRef());
                externalPurlRef.setCategory(it.referenceCategory().name());
                externalPurlRef.setType(it.referenceType().getType());
                externalPurlRef.setComment(it.comment());
                externalPurlRef.setPurl(PurlUtil.strToPackageUrlVo(it.referenceLocator()));
                externalPurlRef.setPkg(existPkg);
                externalPurlRefs.add(externalPurlRef);
            }
        });
        return externalPurlRefs;
    }
}
