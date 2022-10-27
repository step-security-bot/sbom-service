package org.opensourceway.sbom.manager.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.opensourceway.sbom.analyzer.TraceDataAnalyzer;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.SbomApplicationContextHolder;
import org.opensourceway.sbom.manager.dao.ExternalPurlRefRepository;
import org.opensourceway.sbom.manager.dao.ExternalVulRefRepository;
import org.opensourceway.sbom.manager.dao.LicenseRepository;
import org.opensourceway.sbom.manager.dao.PackageRepository;
import org.opensourceway.sbom.manager.dao.ProductConfigRepository;
import org.opensourceway.sbom.manager.dao.ProductRepository;
import org.opensourceway.sbom.manager.dao.ProductStatisticsRepository;
import org.opensourceway.sbom.manager.dao.ProductTypeRepository;
import org.opensourceway.sbom.manager.dao.RawSbomRepository;
import org.opensourceway.sbom.manager.dao.SbomRepository;
import org.opensourceway.sbom.manager.dao.spec.ExternalPurlRefSpecs;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.ExternalVulRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;
import org.opensourceway.sbom.manager.model.Product;
import org.opensourceway.sbom.manager.model.ProductStatistics;
import org.opensourceway.sbom.manager.model.ProductType;
import org.opensourceway.sbom.manager.model.RawSbom;
import org.opensourceway.sbom.manager.model.Sbom;
import org.opensourceway.sbom.manager.model.SbomElementRelationship;
import org.opensourceway.sbom.manager.model.echarts.Edge;
import org.opensourceway.sbom.manager.model.echarts.Graph;
import org.opensourceway.sbom.manager.model.echarts.Node;
import org.opensourceway.sbom.manager.model.spdx.ReferenceCategory;
import org.opensourceway.sbom.manager.model.spdx.ReferenceType;
import org.opensourceway.sbom.manager.model.vo.BinaryManagementVo;
import org.opensourceway.sbom.manager.model.vo.CopyrightVo;
import org.opensourceway.sbom.manager.model.vo.LicenseVo;
import org.opensourceway.sbom.manager.model.vo.PackagePurlVo;
import org.opensourceway.sbom.manager.model.vo.PackageStatisticsVo;
import org.opensourceway.sbom.manager.model.vo.PackageUrlVo;
import org.opensourceway.sbom.manager.model.vo.PackageWithStatisticsVo;
import org.opensourceway.sbom.manager.model.vo.PageVo;
import org.opensourceway.sbom.manager.model.vo.ProductConfigVo;
import org.opensourceway.sbom.manager.model.vo.VulCountVo;
import org.opensourceway.sbom.manager.model.vo.VulnerabilityVo;
import org.opensourceway.sbom.manager.model.vo.request.PublishSbomRequest;
import org.opensourceway.sbom.manager.model.vo.request.QuerySbomPackagesRequest;
import org.opensourceway.sbom.manager.model.vo.response.PublishResultResponse;
import org.opensourceway.sbom.manager.service.SbomService;
import org.opensourceway.sbom.manager.service.reader.SbomReader;
import org.opensourceway.sbom.manager.service.writer.SbomWriter;
import org.opensourceway.sbom.manager.utils.EntityUtil;
import org.opensourceway.sbom.manager.utils.PurlUtil;
import org.opensourceway.sbom.manager.utils.SbomFormat;
import org.opensourceway.sbom.manager.utils.SbomMapperUtil;
import org.opensourceway.sbom.manager.utils.SbomSpecification;
import org.opensourceway.sbom.manager.utils.UrlUtil;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.utils.VersionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@Transactional(rollbackFor = Exception.class)
public class SbomServiceImpl implements SbomService {

    private static final Logger logger = LoggerFactory.getLogger(SbomServiceImpl.class);

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
    private LicenseRepository licenseRepository;

    @Autowired
    private TraceDataAnalyzer traceDataAnalyzer;

    @Autowired
    private ProductStatisticsRepository productStatisticsRepository;

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
            } else if (Objects.equals(SbomConstants.TASK_STATUS_FAILED_FINISH, rawSbom.getTaskStatus())) {
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
    public List<PackageWithStatisticsVo> queryPackageInfoByName(String productName, String packageName, boolean isExactly) {
        String equalPackageName = isExactly ? packageName : null;

        return packageRepository.getPackageInfoByName(productName, equalPackageName, packageName, SbomConstants.MAX_QUERY_LINE)
                .stream()
                .map(PackageWithStatisticsVo::fromPackage)
                .toList();
    }

    @Override
    public Package queryPackageInfoById(String packageId) {
        return packageRepository.findById(UUID.fromString(packageId)).orElse(null);
    }

    @Override
    public PageVo<PackageWithStatisticsVo> getPackageInfoByNameForPage(QuerySbomPackagesRequest req) {
        Pageable pageable = PageRequest.of(req.getPage(), req.getSize()).withSort(Sort.by(Sort.Order.by("name")));
        Page<Package> result = packageRepository.getPackageInfoByNameForPage(req.getProductName(), req.getExactly(),
                req.getPackageName(), req.getVulSeverity(), req.getNoLicense(), req.getMultiLicense(),
                req.getLegalLicense(), req.getLicenseId(), pageable);
        return new PageVo<>(new PageImpl<>(result.stream().map(PackageWithStatisticsVo::fromPackage).toList(),
                result.getPageable(), result.getTotalElements()));
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

        if (referenceCategory == null || referenceCategory == ReferenceCategory.RELATIONSHIP_MANAGER) {
            packageRepository.findById(packageUUID).ifPresentOrElse(pkg -> vo.setRelationshipList(externalPurlRefRepository.queryRelationPackageRef(pkg.getSbom().getId(), pkg.getSpdxId())), () -> vo.setRelationshipList(Lists.newArrayList()));
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
    public PageVo<PackagePurlVo> queryPackageInfoByBinaryViaSpec(String productName, String binaryType, PackageUrlVo purl,
                                                                 String startVersion, String endVersion, Pageable pageable) {
        ReferenceCategory referenceCategory = ReferenceCategory.findReferenceCategory(binaryType);
        if (!ReferenceCategory.BINARY_TYPE.contains(referenceCategory)) {
            throw new RuntimeException("binary type: %s is not support".formatted(binaryType));
        }
        Sbom sbom = sbomRepository.findByProductName(productName)
                .orElseThrow(() -> new RuntimeException("can't find %s's sbom metadata".formatted(productName)));

        Map<String, Pair<String, Boolean>> purlComponents = PurlUtil.generatePurlQueryConditionMap(purl, startVersion, endVersion);
        // 指定版本非空或者版本上下限均为空时，按分页查询处理
        // 指定版本为空并且版本上下限任一非空时，先查出所有符合条件的组件再根据版本范围过滤，最后返回一个假分页
        if (StringUtils.isEmpty(purl.getVersion()) && (StringUtils.isNotEmpty(startVersion) || StringUtils.isNotEmpty(endVersion))) {
            List<ExternalPurlRef> result = externalPurlRefRepository.findAll(
                    ExternalPurlRefSpecs.hasSbomId(sbom.getId())
                            .and(ExternalPurlRefSpecs.hasCategory(binaryType))
                            .and(ExternalPurlRefSpecs.hasType(ReferenceType.PURL.getType()))
                            .and(ExternalPurlRefSpecs.hasPurlComponent(purlComponents))
                            .and(ExternalPurlRefSpecs.withSort("name")));
            // 上下限均非空，startVersion <= version <= endVersion
            if (StringUtils.isNotEmpty(startVersion) && StringUtils.isNotEmpty(endVersion)) {
                result = result.stream()
                        .filter(ref -> VersionUtil.inRange(ref.getPurl().getVersion(), startVersion, endVersion))
                        .toList();
                // 下限为空，上限非空，version <= endVersion
            } else if (StringUtils.isEmpty(startVersion)) {
                result = result.stream()
                        .filter(ref -> VersionUtil.lessThanOrEqualTo(ref.getPurl().getVersion(), endVersion))
                        .toList();
                // 上限为空，下限非空，startVersion <= version
            } else {
                result = result.stream()
                        .filter(ref -> VersionUtil.greaterThanOrEqualTo(ref.getPurl().getVersion(), startVersion))
                        .toList();
            }
            // 最多保留n个结果
            var maxReserveSize = 50;
            if (result.size() > maxReserveSize) {
                logger.warn("received {} components, truncate to {}", result.size(), maxReserveSize);
                result = result.subList(0, maxReserveSize);
            }
            return new PageVo<>(new PageImpl(result.stream().map(PackagePurlVo::fromExternalPurlRef).toList(),
                    PageRequest.of(0, maxReserveSize), result.size()));
        }

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
    public void persistSbomFromTraceData(String productName, String fileName, InputStream inputStream) throws IOException {
        byte[] sbomContent = traceDataAnalyzer.analyze(productName, inputStream);
        readSbomFile(productName, productName + ".spdx.json", sbomContent);
    }

    @Override
    public ProductStatistics queryProductStatistics(String productName) {
        return productStatisticsRepository.findNewestByProductName(productName);
    }

    @Override
    public List<VulCountVo> queryProductVulTrend(String productName, Long startTimestamp, Long endTimestamp) {
        Long oneMonthInMilli = 30L * 24 * 60 * 60 * 1000;
        // if endTimestamp is not set, set it to now
        if (endTimestamp == 0) {
            endTimestamp = System.currentTimeMillis();
        }
        // if startTimestamp is not set, set it to one month before endTimestamp
        if (startTimestamp == 0) {
            startTimestamp = endTimestamp - oneMonthInMilli;
        }
        return productStatisticsRepository.findByProductNameAndCreateTimeRange(productName, startTimestamp, endTimestamp)
                .stream()
                .map(VulCountVo::fromProductStatistics)
                .toList();
    }

    @Override
    public PackageStatisticsVo queryPackageStatisticsByPackageId(String packageId) {
        return packageRepository.findById(UUID.fromString(packageId)).map(PackageStatisticsVo::fromPackage).orElse(null);
    }

    @Override
    public List<LicenseVo> queryLicenseByPackageId(String packageId) {
        List<License> result = licenseRepository.findByPkgId(UUID.fromString(packageId));
        return result.stream().map(LicenseVo::fromLicense).toList();
    }

    @Override
    public List<CopyrightVo> queryCopyrightByPackageId(String packageId) {
        CopyrightVo copyrightVo = new CopyrightVo();
        Package pkg = packageRepository.findById(UUID.fromString(packageId)).orElse(new Package());
        String copyright = pkg.getCopyright();
        if (copyright == null) {
            logger.debug("can not get copyright for package {}.", pkg.getId());
            return List.of(new CopyrightVo());
        }
        String pattern = SbomConstants.COPYRIGHT_REGULAR_EXPRESSION;
        Pattern r = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        Matcher m = r.matcher(copyright);
        if (m.find()) {
            String organization = cleanRegex(m.group(5));
            String startYear = cleanRegex(m.group(3)).split("\\W")[0];

            copyrightVo.setOrganization(organization);
            copyrightVo.setStartYear(startYear);
            copyrightVo.setAdditionalInfo(copyright);
        } else {
            logger.error("copyright of package:{} can not match regular expression, copyright:{}.", pkg.getId(), copyright);
        }
        return List.of(copyrightVo);
    }

    public String cleanRegex(String s) {
        String pattern = "^\\W*|\\W*$";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(s);
        s = m.replaceAll("");
        return s;
    }

    @Override
    public PageVo<VulnerabilityVo> queryVulnerability(String productName, String packageId, String severity, Pageable pageable) {
        Page<ExternalVulRef> result = externalVulRefRepository.findByProductNameAndPackageIdAndSeverity(
                productName, Objects.isNull(packageId) ? null : UUID.fromString(packageId), severity, pageable);
        return new PageVo<>(new PageImpl<>(result.stream().map(VulnerabilityVo::fromExternalVulRef).toList(),
                result.getPageable(),
                result.getTotalElements()));
    }

    @Override
    public Graph queryVulImpact(String productName, String vulId) {
        var graph = new Graph();
        var refs = externalVulRefRepository.findByProductNameAndVulId(productName, vulId);
        if (ObjectUtils.isEmpty(refs)) {
            return graph;
        }

        var vulNode = graph.createVulNode(vulId);
        graph.addNode(vulNode);

        refs.forEach(ref -> {
            var directPurlRef = ref.getPkg().getExternalPurlRefs().stream()
                    .filter(purlRef -> purlRef.getPurl().equals(ref.getPurl()))
                    .findFirst()
                    .orElseThrow();
            var packagePurlRef = ref.getPkg().getExternalPurlRefs().stream()
                    .filter(purlRef -> StringUtils.equals(purlRef.getCategory(), ReferenceCategory.PACKAGE_MANAGER.name()))
                    .findFirst()
                    .orElseThrow();

            Node packageNode;
            if (StringUtils.equals(directPurlRef.getCategory(), ReferenceCategory.PACKAGE_MANAGER.name())) {
                packageNode = graph.createPackageNode(directPurlRef.getPurl().toString());
                if (graph.nodeVisited(packageNode)) {
                    return;
                }
                graph.addNode(packageNode);
                graph.addEdge(new Edge(vulNode.getId(), packageNode.getId()));
                extractTransitiveDepRecursively(graph, packagePurlRef, packageNode);
            } else {
                var directNode = graph.createDepNode(directPurlRef.getPurl().toString());
                if (graph.nodeVisited(directNode)) {
                    return;
                }
                graph.addNode(directNode);
                graph.addEdge(new Edge(vulNode.getId(), directNode.getId()));

                packageNode = graph.createPackageNode(packagePurlRef.getPurl().toString());
                graph.addEdge(new Edge(directNode.getId(), packageNode.getId()));
                if (graph.nodeVisited(packageNode)) {
                    return;
                }
                graph.addNode(packageNode);
                extractTransitiveDepRecursively(graph, packagePurlRef, packageNode);
            }
        });
        return graph;
    }

    private void extractTransitiveDepRecursively(Graph graph, ExternalPurlRef startRef, Node startNode) {
        var transitiveDepSpdxIds = startRef.getPkg().getSbom().getSbomElementRelationships().stream()
                .filter(it -> StringUtils.equals(it.getRelatedElementId(), startRef.getPkg().getSpdxId()))
                .map(SbomElementRelationship::getElementId)
                .toList();
        if (ObjectUtils.isEmpty(transitiveDepSpdxIds)) {
            return;
        }
        startRef.getPkg().getSbom().getPackages().stream()
                .filter(pkg -> transitiveDepSpdxIds.contains(pkg.getSpdxId()))
                .map(Package::getExternalPurlRefs)
                .flatMap(List::stream)
                .filter(ref -> StringUtils.equals(ref.getCategory(), ReferenceCategory.PACKAGE_MANAGER.name()))
                .forEach(ref -> {
                    var node = graph.createTransitiveDepNode(ref.getPurl().toString(), startNode.getY());
                    if (graph.nodeVisited(node)) {
                        return;
                    }
                    graph.addNode(node);
                    graph.addEdge(new Edge(startNode.getId(), node.getId()));
                    startNode.setSize(startNode.getSize() + 2);
                    extractTransitiveDepRecursively(graph, ref, node);
                });
    }
}
