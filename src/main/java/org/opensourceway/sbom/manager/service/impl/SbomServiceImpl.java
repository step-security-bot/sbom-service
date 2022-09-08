package org.opensourceway.sbom.manager.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.TraceDataAnalyzer;
import org.opensourceway.sbom.manager.SbomApplicationContextHolder;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.manager.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.ProductConfigRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.ProductTypeRepository;
import org.opensourceway.sbom.manager.dao.RawSbomRepository;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.dao.spec.ExternalPurlRefSpecs;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.ProductType;
import org.opensourceway.sbom.manager.model.RawSbom;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.spdx.ReferenceType;
import org.opensourceway.sbom.manager.model.vo.BinaryManagementVo;
import org.opensourceway.sbom.manager.model.vo.PackagePurlVo;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.model.vo.PageVo;
import org.opensourceway.sbom.manager.model.vo.ProductConfigVo;
import org.opensourceway.sbom.manager.model.vo.VulnerabilityVo;
import org.opensourceway.sbom.manager.model.vo.request.PublishSbomRequest;
import org.opensourceway.sbom.manager.model.vo.response.PublishResultResponse;
import org.opensourceway.sbom.manager.service.SbomService;
import org.opensourceway.sbom.manager.service.reader.SbomReader;
import org.opensourceway.sbom.manager.service.writer.SbomWriter;
import org.opensourceway.sbom.manager.utils.EntityUtil;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.opensourceway.sbom.manager.utils.SbomFormat;
import org.opensourceway.sbom.manager.utils.SbomSpecification;
import org.opensourceway.sbom.manager.utils.UrlUtil;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.manager.utils.SbomMapperUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional(rollbackFor = Exception.class)
public class SbomServiceImpl implements SbomService {

    @Autowired
    private RawSbomRepository sbomFileRepository;

    @Autowired
    private SbomRepository sbomRepository;

    @Autowired
    private PackageRepository packageRepository;

    @Autowired
    private ExternalPurlRefRepository externalPurlRefRepository;

    @Autowired
    private ProductTypeRepository productTypeRepository;

    @Autowired
    private ProductConfigRepository productConfigRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ExternalVulRefRepository externalVulRefRepository;

    @Autowired
    private TraceDataAnalyzer traceDataAnalyzer;

    @Value("${sbom.service.website.domain}")
    private String sbomWebsiteDomain;

    @Override
    public UUID publishSbom(PublishSbomRequest publishSbomRequest) {
        if (!org.springframework.util.StringUtils.hasText(publishSbomRequest.getProductName())) {
            throw new RuntimeException("product name is empty");
        }
        if (!org.springframework.util.StringUtils.hasText(publishSbomRequest.getSbomContent())) {
            throw new RuntimeException("sbom content is empty");
        }
        Product product = productRepository.findByName(publishSbomRequest.getProductName())
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(publishSbomRequest.getProductName())));
        SbomFormat format = SbomFormat.findSbomFormat(publishSbomRequest.getFormat());
        SbomSpecification specification = SbomSpecification.findSpecification(publishSbomRequest.getSpec(), publishSbomRequest.getSpecVersion());

        RawSbom rawSbom = new RawSbom();
        rawSbom.setSpec(specification != null ? specification.getSpecification().toLowerCase() : null);
        rawSbom.setSpecVersion(specification != null ? specification.getVersion() : null);
        rawSbom.setFormat(format.getFileExtName());
        rawSbom.setProduct(product);
        rawSbom.setValue(publishSbomRequest.getSbomContent().getBytes(StandardCharsets.UTF_8));

        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_WAIT);
        rawSbom.setTaskId(UUID.randomUUID());

        RawSbom oldRawSbom = sbomFileRepository.queryRawSbom(rawSbom);
        if (oldRawSbom != null) {
            // oldRawSbom.getTaskStatus() maybe null for finish job
            if (Objects.nonNull(oldRawSbom.getTaskStatus()) &&
                    !List.of(SbomConstants.TASK_STATUS_FINISH, SbomConstants.TASK_STATUS_FAILED_FINISH)
                            .contains(oldRawSbom.getTaskStatus())) {
                throw new RuntimeException("product: %s has sbom import job in running.".formatted(publishSbomRequest.getProductName()));
            }
            rawSbom.setId(oldRawSbom.getId());
            rawSbom.setCreateTime(oldRawSbom.getCreateTime());
        }
        sbomFileRepository.save(rawSbom);

        return rawSbom.getTaskId();
    }

    /**
     * taskStatus and response status mappings
     * <p>
     * Success[true], finish[false]: WAIT，RUNNING，FAILED, others
     * <p>
     * Success[true], finish[true]: FINISH_PARSE，FINISH
     * <p>
     * Success[false], finish[false]: FAILED_FINISH
     */
    @Override
    public PublishResultResponse getSbomPublishResult(UUID taskId) {
        Optional<RawSbom> rawSbomOptional = sbomFileRepository.findByTaskId(taskId);

        return rawSbomOptional.map(rawSbom -> {
            PublishResultResponse response = new PublishResultResponse();
            if (List.of(SbomConstants.TASK_STATUS_FINISH_PARSE,
                            SbomConstants.TASK_STATUS_FINISH)
                    .contains(rawSbom.getTaskStatus())) {
                response.setSuccess(Boolean.TRUE);
                response.setFinish(Boolean.TRUE);
                response.setSbomRef(UrlUtil.generateSbomUrl(sbomWebsiteDomain, rawSbom.getProduct().getName()));
            } else if (List.of(SbomConstants.TASK_STATUS_FAILED_FINISH)
                    .contains(rawSbom.getTaskStatus())) {
                response.setSuccess(Boolean.FALSE);
                response.setFinish(Boolean.FALSE);
            } else {
                response.setSuccess(Boolean.TRUE);
                response.setFinish(Boolean.FALSE);
            }
            return response;
        }).orElse(
                new PublishResultResponse(Boolean.FALSE,
                        Boolean.FALSE,
                        SbomConstants.TASK_STATUS_NOT_EXISTS,
                        null)
        );
    }

    @Override
    public void readSbomFile(String productName, String fileName, byte[] fileContent) throws IOException {
        SbomFormat format = SbomMapperUtil.fileToExt(fileName);
        SbomSpecification specification = SbomMapperUtil.fileToSpec(format, fileContent);

        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));

        RawSbom rawSbom = new RawSbom();
        rawSbom.setSpec(specification.getSpecification().toLowerCase());
        rawSbom.setSpecVersion(specification.getVersion());
        rawSbom.setFormat(format.getFileExtName());
        rawSbom.setProduct(product);
        rawSbom.setValue(fileContent);

        RawSbom oldRawSbom = sbomFileRepository.queryRawSbom(rawSbom);
        if (oldRawSbom != null) {
            rawSbom.setId(oldRawSbom.getId());
            rawSbom.setCreateTime(oldRawSbom.getCreateTime());
        }
        sbomFileRepository.save(rawSbom);

        SbomReader sbomReader = SbomApplicationContextHolder.getSbomReader(specification.getSpecification());
        sbomReader.read(productName, format, fileContent);
    }

    @Override
    public RawSbom writeSbomFile(String productName, String spec, String specVersion, String format) {
        Product product = productRepository.findByName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(productName)));

        format = StringUtils.lowerCase(format);
        spec = StringUtils.lowerCase(spec);

        if (!SbomFormat.EXT_TO_FORMAT.containsKey(format)) {
            throw new RuntimeException("sbom file format: %s is not support".formatted(format));
        }
        if (SbomSpecification.findSpecification(spec, specVersion) == null) {
            throw new RuntimeException("sbom file specification: %s - %s is not support".formatted(spec, specVersion));
        }

        RawSbom queryCondition = new RawSbom();
        queryCondition.setProduct(product);
        queryCondition.setSpec(spec);
        queryCondition.setSpecVersion(specVersion);
        queryCondition.setFormat(format);

        return sbomFileRepository.queryRawSbom(queryCondition);
    }

    @Override
    public byte[] writeSbom(String productName, String spec, String specVersion, String format) throws IOException {
        format = StringUtils.lowerCase(format);
        spec = StringUtils.lowerCase(spec);

        if (!SbomFormat.EXT_TO_FORMAT.containsKey(format)) {
            throw new RuntimeException("sbom file format: %s is not support".formatted(format));
        }

        SbomSpecification sbomSpec = SbomSpecification.findSpecification(spec, specVersion);
        if (sbomSpec == null) {
            throw new RuntimeException("sbom file specification: %s - %s is not support".formatted(spec, specVersion));
        }

        SbomWriter sbomWriter = SbomApplicationContextHolder.getSbomWriter(sbomSpec.getSpecification());
        return sbomWriter.write(productName, SbomFormat.EXT_TO_FORMAT.get(format));
    }

    @Override
    public PageVo<Package> findPackagesPageable(String productName, int page, int size) {
        Sbom sbom = sbomRepository.findByProductName(productName).orElseThrow(() -> new RuntimeException("can't find %s `s sbom metadata".formatted(productName)));

        Pageable pageable = PageRequest.of(page, size).withSort(Sort.by(Sort.Order.by("name")));
        return new PageVo<>((PageImpl<Package>) packageRepository.findPackagesBySbomIdForPage(sbom.getId(), pageable));
    }

    @Override
    public List<Package> queryPackageInfoByName(String productName, String packageName, boolean isExactly) {
        String equalPackageName = isExactly ? packageName : null;

        return packageRepository.getPackageInfoByName(productName, equalPackageName, packageName, SbomConstants.MAX_QUERY_LINE);
    }

    @Override
    public Package queryPackageInfoById(String packageId) {
        return packageRepository.findById(UUID.fromString(packageId)).orElse(null);
    }

    @Override
    public PageVo<Package> getPackageInfoByNameForPage(String productName, String packageName, Boolean isExactly, int page, int size) {
        String equalPackageName = BooleanUtils.isTrue(isExactly) ? packageName : null;
        Pageable pageable = PageRequest.of(page, size).withSort(Sort.by(Sort.Order.by("name")));

        return new PageVo<>((PageImpl<Package>) packageRepository.getPackageInfoByNameForPage(productName, isExactly, equalPackageName, packageName, pageable));
    }

    @Override
    public BinaryManagementVo queryPackageBinaryManagement(String packageId, String binaryType) {
        UUID packageUUID = UUID.fromString(packageId);
        ReferenceCategory referenceCategory = ReferenceCategory.findReferenceCategory(binaryType);
        if (referenceCategory != null && !ReferenceCategory.BINARY_TYPE.contains(referenceCategory)) {
            throw new RuntimeException("binary type: %s is not support".formatted(binaryType));
        }

        BinaryManagementVo vo = new BinaryManagementVo();
        if (referenceCategory == null || referenceCategory == ReferenceCategory.PACKAGE_MANAGER) {
            vo.setPackageList(externalPurlRefRepository.queryPackageRef(packageUUID, ReferenceCategory.PACKAGE_MANAGER.name(), ReferenceType.PURL.getType()));
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.PROVIDE_MANAGER) {
            vo.setProvideList(externalPurlRefRepository.queryPackageRef(packageUUID, ReferenceCategory.PROVIDE_MANAGER.name(), ReferenceType.PURL.getType()));
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.EXTERNAL_MANAGER) {
            vo.setExternalList(externalPurlRefRepository.queryPackageRef(packageUUID, ReferenceCategory.EXTERNAL_MANAGER.name(), ReferenceType.PURL.getType()));
        }
        return vo;
    }

    @Override
    @Deprecated
    public PageVo<PackagePurlVo> queryPackageInfoByBinary(String productName,
                                                          String binaryType,
                                                          PackageUrlVo purl,
                                                          Pageable pageable) throws Exception {
        ReferenceCategory referenceCategory = ReferenceCategory.findReferenceCategory(binaryType);
        if (!ReferenceCategory.BINARY_TYPE.contains(referenceCategory)) {
            throw new RuntimeException("binary type: %s is not support".formatted(binaryType));
        }

        Pair<String, Boolean> purlQueryCondition = PurlUtil.generatePurlQueryCondition(purl);

        Page<Map> result = packageRepository.queryPackageInfoByBinary(productName,
                binaryType,
                purlQueryCondition.getSecond(),
                purlQueryCondition.getFirst(),
                purlQueryCondition.getFirst(),
                pageable);

        return new PageVo<>((PageImpl<PackagePurlVo>) EntityUtil.castEntity(result, PackagePurlVo.class));
    }

    @Override
    public PageVo<PackagePurlVo> queryPackageInfoByBinaryViaSpec(String productName,
                                                                 String binaryType,
                                                                 PackageUrlVo purl,
                                                                 Pageable pageable) {
        ReferenceCategory referenceCategory = ReferenceCategory.findReferenceCategory(binaryType);
        if (!ReferenceCategory.BINARY_TYPE.contains(referenceCategory)) {
            throw new RuntimeException("binary type: %s is not support".formatted(binaryType));
        }
        Sbom sbom = sbomRepository.findByProductName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's sbom metadata".formatted(productName)));

        Map<String, Pair<String, Boolean>> purlComponents = PurlUtil.generatePurlQueryConditionMap(purl);
        Page<ExternalPurlRef> result = externalPurlRefRepository.findAll(
                ExternalPurlRefSpecs.hasSbomId(sbom.getId())
                        .and(ExternalPurlRefSpecs.hasCategory(binaryType))
                        .and(ExternalPurlRefSpecs.hasType(ReferenceType.PURL.getType()))
                        .and(ExternalPurlRefSpecs.hasPurlComponent(purlComponents))
                        .and(ExternalPurlRefSpecs.withSort("name")),
                pageable);

        return new PageVo<>(new PageImpl(result.stream().map(PackagePurlVo::fromExternalPurlRef).collect(Collectors.toList()),
                result.getPageable(),
                result.getTotalElements()));
    }

    @Override
    public List<String> queryProductType() {
        return productTypeRepository.findAll().stream().map(ProductType::getType).toList();
    }

    @Override
    public List<ProductConfigVo> queryProductConfigByProductType(String productType) {
        return productConfigRepository.findByProductTypeOrderByOrdAsc(productType)
                .stream()
                .map(it -> new ProductConfigVo(it.getName(), it.getLabel(), it.getValueType(), it.getOrd()))
                .toList();
    }

    public Product queryProductByFullAttributes(Map<String, ?> attributes) throws JsonProcessingException {
        String attr = Mapper.objectMapper.writeValueAsString(attributes);
        return productRepository.queryProductByFullAttributes(attr);
    }

    @Override
    public PageVo<VulnerabilityVo> queryVulnerabilityByPackageId(String packageId, Pageable pageable) {
        Page<ExternalVulRef> result = externalVulRefRepository.findByPackageId(UUID.fromString(packageId), pageable);
        return new PageVo<>(new PageImpl<>(result.stream().map(VulnerabilityVo::fromExternalVulRef).toList(),
                result.getPageable(),
                result.getTotalElements()));
    }

    @Override
    public void persistSbomFromTraceData(String productName, String fileName, InputStream inputStream) throws IOException {
        byte[] sbomContent = traceDataAnalyzer.analyze(productName, fileName, inputStream);
        readSbomFile(productName, productName + ".spdx.json", sbomContent);
    }

}
