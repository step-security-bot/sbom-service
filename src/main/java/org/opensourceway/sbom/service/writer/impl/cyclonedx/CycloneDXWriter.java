package org.opensourceway.sbom.service.writer.impl.cyclonedx;

import org.apache.commons.lang3.ObjectUtils;
import org.opensourceway.sbom.api.writer.SbomWriter;
import org.opensourceway.sbom.dao.SbomRepository;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.cyclonedx.Algorithm;
import org.opensourceway.sbom.model.cyclonedx.Component;
import org.opensourceway.sbom.model.cyclonedx.ComponentType;
import org.opensourceway.sbom.model.cyclonedx.CycloneDXDocument;
import org.opensourceway.sbom.model.cyclonedx.Dependency;
import org.opensourceway.sbom.model.cyclonedx.ExternalReference;
import org.opensourceway.sbom.model.cyclonedx.ExternalReferenceType;
import org.opensourceway.sbom.model.cyclonedx.Hash;
import org.opensourceway.sbom.model.cyclonedx.License;
import org.opensourceway.sbom.model.cyclonedx.Manufacture;
import org.opensourceway.sbom.model.cyclonedx.Metadata;
import org.opensourceway.sbom.model.cyclonedx.Patch;
import org.opensourceway.sbom.model.cyclonedx.PatchDiff;
import org.opensourceway.sbom.model.cyclonedx.PatchType;
import org.opensourceway.sbom.model.cyclonedx.Pedigree;
import org.opensourceway.sbom.model.cyclonedx.Property;
import org.opensourceway.sbom.model.cyclonedx.Rating;
import org.opensourceway.sbom.model.cyclonedx.Supplier;
import org.opensourceway.sbom.model.cyclonedx.Tool;
import org.opensourceway.sbom.model.cyclonedx.VulnerabilityMethod;
import org.opensourceway.sbom.model.cyclonedx.VulnerabilitySeverity;
import org.opensourceway.sbom.model.entity.Checksum;
import org.opensourceway.sbom.model.entity.ExternalPurlRef;
import org.opensourceway.sbom.model.entity.File;
import org.opensourceway.sbom.model.entity.Package;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.entity.SbomCreator;
import org.opensourceway.sbom.model.entity.SbomElementRelationship;
import org.opensourceway.sbom.model.entity.VulScore;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.pojo.vo.sbom.PackageUrlVo;
import org.opensourceway.sbom.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.model.spdx.RelationshipType;
import org.opensourceway.sbom.utils.PurlUtil;
import org.opensourceway.sbom.utils.SbomMapperUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service(value = SbomConstants.CYCLONEDX_NAME + SbomConstants.WRITER_NAME)
@Transactional(rollbackFor = Exception.class)
public class CycloneDXWriter implements SbomWriter {
    private static final Logger logger = LoggerFactory.getLogger(CycloneDXWriter.class);

    private static final String BOM_FORMAT = "CycloneDX";

    private static final String CYCLONEDX_VERSION = "1.4";

    private static final String SERIAL_NUMBER_PREFIX = "urn:uuid:";

    private static final String RELATION_CATEGORY = "RelationCategory";

    private static final String SUMMARY = "summary";

    private static final String TOOL = "Tool";

    private static final String ORGANIZATION = "Organization";

    private static final Integer VERSION = 1;

    @Autowired
    private SbomRepository sbomRepository;

    @Override
    public byte[] write(String productName, SbomFormat format) throws IOException {
        Sbom sbom = sbomRepository.findByProductName(productName).orElseThrow(() -> new RuntimeException("can't find %s's sbom metadata".formatted(productName)));
        CycloneDXDocument document = new CycloneDXDocument(SERIAL_NUMBER_PREFIX + sbom.getId().toString());

        document.setBomFormat(BOM_FORMAT);
        document.setSpecVersion(CYCLONEDX_VERSION);
        document.setVersion(VERSION);
        setMetadata(sbom, document);
        setComponents(sbom, document);
        setDependencies(sbom, document);

        return SbomMapperUtil.writeAsBytes(document, format);
    }

    private void setMetadata(Sbom sbom, CycloneDXDocument document) {
        Metadata metadata = new Metadata();
        metadata.setTimestamp(sbom.getCreated());
        setToolsAndManufacture(sbom, metadata);
        metadata.setLicenses(List.of(new License(sbom.getDataLicense())));
        metadata.setComponent(parseMetaDataComponent(sbom));
        document.setMetadata(metadata);
    }

    private void setToolsAndManufacture(Sbom sbom, Metadata metadata) {
        List<String> creators = sbom.getSbomCreators().stream().map(SbomCreator::getName).toList();
        Tool tool = new Tool();
        try {
            for (String creator : creators) {
                if (creator.startsWith(TOOL)) {
                    tool.setVersion(creator.split("-", 2)[1].strip());
                    tool.setName(creator.split("-", 2)[0].split(":")[1].strip());
                } else if (creator.startsWith(ORGANIZATION)) {
                    metadata.setManufacture(new Manufacture(creator.split(":")[1].strip()));
                }
            }
        } catch (Exception e) {
            logger.error("parse creators error for sbom {}", sbom.getId());
        }
        metadata.setTools(List.of(tool));
    }

    private Component parseMetaDataComponent(Sbom sbom) {
        Product product = sbom.getProduct();
        String productType = product.getAttribute().get(SbomConstants.PRODUCT_TYPE);
        String name = product.getName();
        Component component = new Component(name);
        component.setVersion(product.getAttribute().get(SbomConstants.PRODUCT_ATTRIBUTE_VERSION));
        if (SbomConstants.PRODUCT_OPENEULER_NAME.equals(productType) || SbomConstants.PRODUCT_OPENHARMONY_NAME.equals(productType)) {
            component.setType(ComponentType.OPERATING_SYSTEM);
        } else {
            component.setType(ComponentType.APPLICATION);
        }
        return component;
    }

    private Component transformPackage(Package pkg, Map<String, List<String>> pkgPatchMap) {
        Component component = new Component(pkg.getName());
        component.setCopyright(pkg.getCopyright());

        setComponentSupplier(pkg, component);
        component.setDescription(pkg.getDescription());
        component.setProperties(new ArrayList<>(Collections.singletonList(new Property(SUMMARY, pkg.getSummary()))));
        setComponentHashes(pkg, component);
        setExternalReferenceAndComponents(pkg, component);
        component.setLicenses(List.of(new License(pkg.getLicenseConcluded())));
        PackageUrlVo purlVo = pkg.getExternalPurlRefs().stream()
                .filter(externalPurlRef -> externalPurlRef.getCategory().equals(ReferenceCategory.PACKAGE_MANAGER.toString())).map(ExternalPurlRef::getPurl).toList().get(0);

        setPurl(purlVo, component);
        component.setGroup(purlVo.getNamespace());
        component.setVersion(pkg.getVersion());
        component.setType(ComponentType.LIBRARY);
        component.setBomRef(pkg.getSpdxId());
        List<Patch> patches = new ArrayList<>();
        if (ObjectUtils.isNotEmpty(pkgPatchMap.get(pkg.getSpdxId()))) {
            for (String patchUrl : pkgPatchMap.get(pkg.getSpdxId())) {
                Patch patch = new Patch(PatchType.CHERRY_PICK, new PatchDiff(patchUrl));
                patches.add(patch);
            }
            component.setPedigree(new Pedigree(patches));
        }
        return component;
    }

    private void setComponents(Sbom sbom, CycloneDXDocument document) {
        List<Component> components = new ArrayList<>();
        List<Package> packages = sbom.getPackages();
        Map<String, List<String>> pkgPatchMap = getPkgPatchMap(sbom);
        for (Package pkg : packages) {
            components.add(transformPackage(pkg, pkgPatchMap));
        }
        document.setComponents(components);
    }

    private Map<String, List<String>> getPkgPatchMap(Sbom sbom) {
        List<SbomElementRelationship> sbomElementRelationships = sbom.getSbomElementRelationships().stream()
                .filter(sbomElementRelationship -> sbomElementRelationship.getRelationshipType().equals(RelationshipType.PATCH_APPLIED.name())).toList();
        List<File> files = sbom.getFiles();
        Map<String, List<String>> pkgPatchMap = new HashMap<>();
        Map<String, String> patchUrlMap = new HashMap<>();
        for (File file : files) {
            patchUrlMap.put(file.getSpdxId(), file.getFileName());
        }
        for (SbomElementRelationship sbomElementRelationship : sbomElementRelationships) {
            if (pkgPatchMap.containsKey(sbomElementRelationship.getRelatedElementId())) {
                pkgPatchMap.get(sbomElementRelationship.getRelatedElementId()).add(patchUrlMap.get(sbomElementRelationship.getElementId()));
            } else {
                pkgPatchMap.put(sbomElementRelationship.getRelatedElementId(), new ArrayList<>(Collections.singletonList(patchUrlMap.get(sbomElementRelationship.getElementId()))));
            }
        }
        return pkgPatchMap;
    }


    private void setExternalReferenceAndComponents(Package pkg, Component component) {
        List<ExternalPurlRef> externalPurlRefs = pkg.getExternalPurlRefs();
        if (ObjectUtils.isEmpty(externalPurlRefs)) {
            return;
        }
        List<ExternalReference> externalReferences = new ArrayList<>();

        for (ExternalPurlRef externalPurlRef : externalPurlRefs) {
            if (externalPurlRef.getCategory().equals(ReferenceCategory.PACKAGE_MANAGER.name())) {
                continue;
            }
            if (externalPurlRef.getCategory().equals(ReferenceCategory.SOURCE_MANAGER.name())) {
                ExternalReference externalReference = new ExternalReference(externalPurlRef.getPurl().getName(), null, ExternalReferenceType.VCS, null);
                externalReferences.add(externalReference);
            } else {
                setNestedComponents(externalPurlRef, component);
            }
        }

        if (ObjectUtils.isNotEmpty(pkg.getHomepage())) {
            ExternalReference homePage = new ExternalReference(pkg.getHomepage(), null, ExternalReferenceType.WEBSITE, null);
            externalReferences.add(homePage);
        }
        if (ObjectUtils.isNotEmpty(pkg.getDownloadLocation())) {
            ExternalReference downloadLocation = new ExternalReference(pkg.getDownloadLocation(), null, ExternalReferenceType.DISTRIBUTION, null);
            externalReferences.add(downloadLocation);
        }
        component.setExternalReferences(externalReferences);
    }

    private void setNestedComponents(ExternalPurlRef externalPurlRef, Component component) {
        Component nestedComponent = new Component();
        nestedComponent.setType(ComponentType.LIBRARY);
        nestedComponent.setPurl(PurlUtil.canonicalizePurl(externalPurlRef.getPurl()));
        nestedComponent.setGroup(externalPurlRef.getPurl().getNamespace());
        nestedComponent.setName(externalPurlRef.getPurl().getName());
        nestedComponent.setVersion(externalPurlRef.getPurl().getVersion());
        if (ObjectUtils.isNotEmpty(nestedComponent.getProperties())) {
            nestedComponent.getProperties().add(new Property(RELATION_CATEGORY, externalPurlRef.getCategory()));
        } else {
            nestedComponent.setProperties(new ArrayList<>(Collections.singletonList(new Property(RELATION_CATEGORY, externalPurlRef.getCategory()))));
        }
        if (ObjectUtils.isNotEmpty(component.getComponents())) {
            component.getComponents().add(nestedComponent);
        } else {
            component.setComponents(new ArrayList<>(Collections.singletonList(nestedComponent)));
        }
    }

    private void setComponentSupplier(Package pkg, Component component) {
        try {
            if (ObjectUtils.isNotEmpty(pkg.getSupplier())) {
                Supplier supplier = new Supplier(null, pkg.getSupplier().split(":", 2)[1].strip());
                component.setSupplier(supplier);
            }
        } catch (Exception e) {
            logger.error("parse supplier error for package {}", pkg.getId());
        }
    }

    private void setComponentHashes(Package pkg, Component component) {
        List<Checksum> checksums = pkg.getChecksums();
        List<Hash> hashes = new ArrayList<>();
        for (Checksum checksum : checksums) {
            String algorithm = checksum.getAlgorithm();
            String value = checksum.getValue();
            Hash hash = new Hash(Algorithm.valueOf(algorithm), value);
            hashes.add(hash);
        }
        component.setHashes(hashes);
    }

    private void setPurl(PackageUrlVo packageUrlVo, Component component) {
        String purl = PurlUtil.canonicalizePurl(packageUrlVo);
        component.setPurl(purl);
    }

    private void setDependencies(Sbom sbom, CycloneDXDocument document) {
        List<SbomElementRelationship> sbomElementRelationships = sbom.getSbomElementRelationships().stream()
                .filter(sbomElementRelationship -> sbomElementRelationship.getRelationshipType().equals(RelationshipType.DEPENDS_ON.name())).toList();
        List<Dependency> dependencies = new ArrayList<>();

        Map<String, List<String>> sbomRelationsMap = new HashMap<>();
        for (SbomElementRelationship sbomElementRelationship : sbomElementRelationships) {
            if (sbomRelationsMap.containsKey(sbomElementRelationship.getElementId())) {
                sbomRelationsMap.get(sbomElementRelationship.getElementId()).add(sbomElementRelationship.getRelatedElementId());
            } else {
                sbomRelationsMap.put(sbomElementRelationship.getElementId(), new ArrayList<>(Collections.singletonList(sbomElementRelationship.getRelatedElementId())));
            }
        }
        for (Component component : document.getComponents()) {
            Dependency dependency = new Dependency();
            dependency.setRef(component.getBomRef());
            dependency.setDependsOn(sbomRelationsMap.get(component.getBomRef()));
            dependencies.add(dependency);
        }
        document.setDependencies(dependencies);
    }

    private Rating transformVulRatings(VulScore vulScore) {
        return new Rating(vulScore.getScore().toString(),
                VulnerabilitySeverity.valueOf(vulScore.getSeverity()),
                VulnerabilityMethod.valueOf(vulScore.getScoringSystem()),
                vulScore.getVector());
    }
}
