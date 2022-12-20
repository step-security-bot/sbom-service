package org.opensourceway.sbom.controller;


import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.SbomManagerApplication;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;
import org.opensourceway.sbom.utils.Mapper;
import org.opensourceway.sbom.utils.SbomApplicationContextHolder;
import org.opensourceway.sbom.utils.TestCommon;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
public class PublishControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RawSbomRepository sbomFileRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private TestCommon testCommon;

    @Test
    public void uploadSbomFileFailed() throws Exception {
        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME);
        MockMultipartFile file = new MockMultipartFile("uploadFileName", TestConstants.SAMPLE_UPLOAD_FILE_NAME
                , "json", classPathResource.getInputStream());

        this.mockMvc
                .perform(multipart("/sbom-api/uploadSbomFile").file(file)
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME + "ERROR")
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("can't find mindsporeTestERROR's product metadata"));
    }

    @Test
    public void publishSbomProductNameIsEmpty() throws Exception {
        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();

        this.mockMvc
                .perform(post("/sbom-api/publishSbomFile")
                        .content(Mapper.objectMapper.writeValueAsString(publishSbomRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorInfo").value("product name is empty"))
                .andExpect(jsonPath("$.taskId").isEmpty());
    }

    @Test
    public void publishSbomContentIsEmpty() throws Exception {
        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();
        publishSbomRequest.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);

        this.mockMvc
                .perform(post("/sbom-api/publishSbomFile")
                        .content(Mapper.objectMapper.writeValueAsString(publishSbomRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorInfo").value("sbom content is empty"))
                .andExpect(jsonPath("$.taskId").isEmpty());
    }

    @Test
    public void publishSbomProductNameIsError() throws Exception {
        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();
        publishSbomRequest.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "1");
        publishSbomRequest.setSbomContent("{}");

        this.mockMvc
                .perform(post("/sbom-api/publishSbomFile")
                        .content(Mapper.objectMapper.writeValueAsString(publishSbomRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorInfo").value("can't find %s1's product metadata".formatted(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)))
                .andExpect(jsonPath("$.taskId").isEmpty());
    }

    @Test
    public void publishSbomContentSuccess() throws Exception {
        testCommon.cleanPublishRawSbomData(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);

        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();
        publishSbomRequest.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);

        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_UPLOAD_FILE_NAME);
        publishSbomRequest.setSbomContent(IOUtils.toString(classPathResource.getInputStream(), StandardCharsets.UTF_8));

        this.mockMvc
                .perform(post("/sbom-api/publishSbomFile")
                        .content(Mapper.objectMapper.writeValueAsString(publishSbomRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.errorInfo").isEmpty())
                .andExpect(jsonPath("$.taskId").isNotEmpty());
    }

    @Test
    public void getPublishAsyncResult() throws Exception {
        Product product = productRepository.findByName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)));

        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();
        RawSbom condition = new RawSbom();
        condition.setSpec(publishSbomRequest.getSpec().toLowerCase());
        condition.setSpecVersion(publishSbomRequest.getSpecVersion());
        condition.setFormat(publishSbomRequest.getFormat());
        condition.setProduct(product);
        RawSbom rawSbom = sbomFileRepository.queryRawSbom(condition);

        this.mockMvc
                .perform(get("/sbom-api/querySbomPublishResult/%s".formatted(rawSbom.getTaskId()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(Boolean.TRUE))
                .andExpect(jsonPath("$.finish").value(Boolean.FALSE))
                .andExpect(jsonPath("$.errorInfo").isEmpty())
                .andExpect(jsonPath("$.sbomRef").isEmpty());
    }


    @Test
    public void getPublishAsyncResultWrongTaskId() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/querySbomPublishResult/%s".formatted("0ee6f042-11f7-488a-b8d4-3729d108abdc"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(Boolean.FALSE))
                .andExpect(jsonPath("$.finish").value(Boolean.FALSE))
                .andExpect(jsonPath("$.errorInfo").value("task not exists"))
                .andExpect(jsonPath("$.sbomRef").isEmpty());
    }

    @Test
    public void uploadSbomTraceData() throws Exception {
        ClassPathResource classPathResource = new ClassPathResource(TestConstants.SAMPLE_UPLOAD_TRACE_DATA_NAME);
        MockMultipartFile file = new MockMultipartFile("uploadFileName", TestConstants.SAMPLE_UPLOAD_TRACE_DATA_NAME
                , "json", classPathResource.getInputStream());

        this.mockMvc
                .perform(multipart("/sbom-api/uploadSbomTraceData").file(file)
                        .param("productName", TestConstants.SAMPLE_MINDSPORE_TRACER_PRODUCT_NAME)
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andDo(print())
                .andExpect(status().isAccepted());
    }
}

