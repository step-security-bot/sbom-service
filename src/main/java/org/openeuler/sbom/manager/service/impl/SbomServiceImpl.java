package org.openeuler.sbom.manager.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.openeuler.sbom.manager.SbomApplicationContextHolder;
import org.openeuler.sbom.manager.constant.SbomConstants;
import org.openeuler.sbom.manager.dao.ExternalPurlRefRepository;
import org.openeuler.sbom.manager.dao.ExternalVulRefRepository;
import org.openeuler.sbom.manager.dao.PackageRepository;
import org.openeuler.sbom.manager.dao.ProductConfigRepository;
import org.openeuler.sbom.manager.dao.ProductRepository;
import org.openeuler.sbom.manager.dao.ProductTypeRepository;
import org.openeuler.sbom.manager.dao.RawSbomRepository;
import org.openeuler.sbom.manager.dao.SbomRepository;
import org.openeuler.sbom.manager.dao.spec.ExternalPurlRefSpecs;
import org.openeuler.sbom.manager.model.ExternalPurlRef;
import org.openeuler.sbom.manager.model.ExternalVulRef;
import org.openeuler.sbom.manager.model.Package;
import org.openeuler.sbom.manager.model.Product;
import org.openeuler.sbom.manager.model.ProductType;
import org.openeuler.sbom.manager.model.RawSbom;
import org.openeuler.sbom.manager.model.Sbom;
import org.openeuler.sbom.manager.model.spdx.ReferenceCategory;
import org.openeuler.sbom.manager.model.vo.BinaryManagementVo;
import org.openeuler.sbom.manager.model.vo.PackagePurlVo;
import org.openeuler.sbom.manager.model.vo.PackageUrlVo;
import org.openeuler.sbom.manager.model.vo.PageVo;
import org.openeuler.sbom.manager.model.vo.ProductConfigVo;
import org.openeuler.sbom.manager.model.vo.VulnerabilityVo;
import org.openeuler.sbom.manager.model.vo.request.PublishSbomRequest;
import org.openeuler.sbom.manager.model.vo.response.PublishResultResponse;
import org.openeuler.sbom.manager.service.SbomService;
import org.openeuler.sbom.manager.service.reader.SbomReader;
import org.openeuler.sbom.manager.service.writer.SbomWriter;
import org.openeuler.sbom.manager.utils.EntityUtil;
import org.openeuler.sbom.manager.utils.PurlUtil;
import org.openeuler.sbom.manager.utils.SbomFormat;
import org.openeuler.sbom.manager.utils.SbomSpecification;
import org.openeuler.sbom.manager.utils.UrlUtil;
import org.openeuler.sbom.utils.Mapper;
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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.openeuler.sbom.manager.utils.SbomMapperUtil.fileToExt;
import static org.openeuler.sbom.manager.utils.SbomMapperUtil.fileToSpec;

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

    @Value("${sbom.service.website.domain}")
    private String sbomWebsiteDomain;

    @Override
    public UUID publishSbom(PublishSbomRequest publishSbomRequest) throws IOException {
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
        rawSbom.setSpec(specification.getSpecification().toLowerCase());
        rawSbom.setSpecVersion(specification.getVersion());
        rawSbom.setFormat(format.getFileExtName());
        rawSbom.setProduct(product);
        rawSbom.setValue(publishSbomRequest.getSbomContent().getBytes(StandardCharsets.UTF_8));

        rawSbom.setTaskStatus(SbomConstants.TASK_STATUS_WAIT);
        rawSbom.setTaskId(UUID.randomUUID());

        RawSbom oldRawSbom = sbomFileRepository.queryRawSbom(rawSbom);
        if (oldRawSbom != null) {
            rawSbom.setId(oldRawSbom.getId());
            rawSbom.setCreateTime(oldRawSbom.getCreateTime());
        }
        sbomFileRepository.save(rawSbom);

        // TODO 1. sbom发布逻辑需要异步处理，以下SBOM元数据解析和入库逻辑待拆分到异步定时任务中被调用
        // TODO 2. rawSbom中的taskId是否可作为quartz任务的taskId? 这样可以用于后续排查僵死任务
        // TODO 3. rawSbom中的taskStatus后续需要实现互斥和幂等逻辑；wait和running状态的任务，不允许二次发布；finish的进行清理+导入
        SbomReader sbomReader = SbomApplicationContextHolder.getSbomReader(specification.getSpecification());
        sbomReader.read(product.getName(), format, rawSbom.getValue());

        return rawSbom.getTaskId();
    }

    @Override
    public PublishResultResponse getSbomPublishResult(UUID taskId) {
        Optional<RawSbom> rawSbomOptional = sbomFileRepository.findByTaskId(taskId);

        return rawSbomOptional.map(rawSbom -> {
            PublishResultResponse response = new PublishResultResponse();
            response.setSuccess(Boolean.TRUE);
            if (StringUtils.equalsIgnoreCase(rawSbom.getTaskStatus(), SbomConstants.TASK_STATUS_FINISH)) {
                response.setFinish(Boolean.TRUE);
                response.setSbomRef(UrlUtil.generateSbomUrl(sbomWebsiteDomain, rawSbom.getProduct().getName()));
            } else {
                response.setFinish(Boolean.TRUE);
                response.setSbomRef(UrlUtil.generateSbomUrl(sbomWebsiteDomain, rawSbom.getProduct().getName()));

                // TODO SBOM元数据解析和入库逻辑待拆分到异步定时任务中后，running和wait状态都返回Finish为false
                // response.setFinish(Boolean.FALSE);
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
        SbomFormat format = fileToExt(fileName);
        SbomSpecification specification = fileToSpec(format, fileContent);

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
            vo.setPackageList(externalPurlRefRepository.queryPackageRef(packageUUID, ReferenceCategory.PACKAGE_MANAGER.name()));
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.PROVIDE_MANAGER) {
            vo.setProvideList(externalPurlRefRepository.queryPackageRef(packageUUID, ReferenceCategory.PROVIDE_MANAGER.name()));
        }

        if (referenceCategory == null || referenceCategory == ReferenceCategory.EXTERNAL_MANAGER) {
            vo.setExternalList(externalPurlRefRepository.queryPackageRef(packageUUID, ReferenceCategory.EXTERNAL_MANAGER.name()));
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

}
