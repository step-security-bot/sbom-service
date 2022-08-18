package org.openeuler.sbom.manager.controller;


import org.junit.jupiter.api.Test;
import org.openeuler.sbom.manager.SbomApplicationContextHolder;
import org.openeuler.sbom.manager.SbomManagerApplication;
import org.openeuler.sbom.manager.TestConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
public class PublishControllerTests {

    @Autowired
    private MockMvc mockMvc;

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
}

