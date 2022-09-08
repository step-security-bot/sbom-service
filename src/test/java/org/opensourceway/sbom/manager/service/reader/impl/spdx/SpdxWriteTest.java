package org.opensourceway.sbom.manager.service.reader.impl.spdx;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.manager.utils.TestCommon;
import org.opensourceway.sbom.manager.TestConstants;
import org.opensourceway.sbom.constants.SbomConstants;
import org.opensourceway.sbom.manager.dao.VulnerabilityRepository;
import org.opensourceway.sbom.manager.model.Vulnerability;
import org.opensourceway.sbom.manager.model.spdx.SpdxDocument;
import org.opensourceway.sbom.manager.service.writer.impl.spdx.SpdxWriter;
import org.opensourceway.sbom.manager.utils.SbomFormat;
import org.opensourceway.sbom.utils.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SpdxWriteTest {

    private static final String PRODUCT_ID = "SpdxWriterTest";

    @Autowired
    @Qualifier(SbomConstants.SPDX_NAME + SbomConstants.READER_NAME)
    private SpdxReader spdxReader;


    @Autowired
    @Qualifier(SbomConstants.SPDX_NAME + SbomConstants.WRITER_NAME)
    private SpdxWriter spdxWriter;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Test
    @Order(1)
    public void insertSbom() throws IOException {
        Vulnerability vulnerability = vulnerabilityRepository
                .findByVulIdAndSource("cve-2022-00000", "CVE_MANAGER").orElse(new Vulnerability());
        vulnerability.setVulId("cve-2022-00000");
        vulnerability.setType("cve");
        vulnerability.setSource("CVE_MANAGER");
        vulnerabilityRepository.save(vulnerability);

        spdxReader.read(PRODUCT_ID, new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME).getFile());
    }

    @Test
    public void writeJsonSbom() throws IOException {
        byte[] result = spdxWriter.write(PRODUCT_ID, SbomFormat.EXT_TO_FORMAT.get("json"));
        SpdxDocument spdxDocument = Mapper.jsonSbomMapper.readValue(result, SpdxDocument.class);
        TestCommon.assertSpdxDocument(spdxDocument);
    }

    @Test
    public void writeYamlSbom() throws IOException {
        byte[] result = spdxWriter.write(PRODUCT_ID, SbomFormat.EXT_TO_FORMAT.get("yaml"));
        SpdxDocument spdxDocument = Mapper.yamlSbomMapper.readValue(result, SpdxDocument.class);
        TestCommon.assertSpdxDocument(spdxDocument);
    }

    @Test
    public void writeXmlSbom() throws IOException {
        byte[] result = spdxWriter.write(PRODUCT_ID, SbomFormat.EXT_TO_FORMAT.get("xml"));
        SpdxDocument spdxDocument = Mapper.xmlSbomMapper.readValue(result, SpdxDocument.class);
        TestCommon.assertSpdxDocument(spdxDocument);
    }
}