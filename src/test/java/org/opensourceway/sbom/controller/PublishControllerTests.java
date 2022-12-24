package org.opensourceway.sbom.controller;


import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opensourceway.sbom.SbomManagerApplication;
import org.opensourceway.sbom.TestConstants;
import org.opensourceway.sbom.dao.ProductConfigRepository;
import org.opensourceway.sbom.dao.ProductConfigValueRepository;
import org.opensourceway.sbom.dao.ProductRepository;
import org.opensourceway.sbom.dao.ProductTypeRepository;
import org.opensourceway.sbom.dao.RawSbomRepository;
import org.opensourceway.sbom.model.constants.PublishSbomConstants;
import org.opensourceway.sbom.model.entity.Product;
import org.opensourceway.sbom.model.entity.ProductConfig;
import org.opensourceway.sbom.model.entity.RawSbom;
import org.opensourceway.sbom.model.enums.SbomContentType;
import org.opensourceway.sbom.model.pojo.request.sbom.AddProductRequest;
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
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.hamcrest.Matchers.containsString;
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
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PublishControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RawSbomRepository sbomFileRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private TestCommon testCommon;

    @Autowired
    private ProductTypeRepository productTypeRepository;

    @Autowired
    private ProductConfigValueRepository productConfigValueRepository;

    @Autowired
    private ProductConfigRepository productConfigRepository;

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
        publishSbomContentErrorCommonFunc(null,
                null,
                null,
                "product name is empty");
    }

    @Test
    public void publishSbomContentIsEmpty() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                null,
                null,
                "sbom content is empty");
    }

    @Test
    public void publishSbomContentTypeIsEmpty() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "{}",
                null,
                "sbom content type is empty");
    }

    @Test
    public void publishSbomContentTypeIsError() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "{}",
                "x",
                "Invalid sbomContentType: x, allowed types: %s".formatted(
                        Arrays.stream(SbomContentType.values()).map(SbomContentType::getType).toList()));
    }

    @Test
    public void publishSbomProductNameIsError() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "1",
                "{}",
                SbomContentType.SPDX_2_2_JSON_SBOM.getType(),
                "can't find %s1's product metadata".formatted(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME));
    }

    @Test
    public void publishSbomContentDefinitionFileNotBase64String() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "x",
                SbomContentType.DEFINITION_FILE.getType(),
                "sbomContent is not a valid base64 encoded string");
    }

    @Test
    public void publishSbomContentTraceDataNotBase64String() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "x",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "sbomContent is not a valid base64 encoded string");
    }

    @Test
    public void publishSbomContentDefinitionFileNotTar() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "MQ==",
                SbomContentType.DEFINITION_FILE.getType(),
                "Failed to extract sbomContent tar");
    }

    @Test
    public void publishSbomContentTraceDataNotTar() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "MQ==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "Failed to extract sbomContent tar");
    }

    @Test
    public void publishSbomContentDefinitionFileDefinitionFileTarNotExist() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAAyvJLdArSSzSS69ioBkwAAIzExMGAzMDQ3NTQzBtYGAIFgcBQzNDBkMTYxNTM0MTIzNzBqCsuakRg4IB7ZyEAKXFQO8rKDAkpuRm5tHDwsEF5Ls5IAzmt+d28x5yEGE5oP3U6oHcPn/baR4cPQIz/hmKySoIn1XRzt20W+97sFXEzZ5rQS9V3bptvTv3/vcKXH6r6srnkO11XyQ0ty/ur90z7/WfE5Znpz+t+n1cAW7Ln3e8+9tjnzBoDIwnR8EoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AYAgCq+cxBACgAAA==",
                SbomContentType.DEFINITION_FILE.getType(),
                "[%s] doesn't exist or is not a regular file".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
    }

    @Test
    public void publishSbomContentTraceDataDefinitionFileTarNotExist() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAAyvJLdArSSzSS69ioBkwAAIzExMGAzMDQ3NTQzBtYGAIFgcBQzNDBkMTYxNTM0MTIzNzBqCsuakRg4IB7ZyEAKXFQO8rKDAkpuRm5tHDwsEF5Ls5IAzmt+d28x5yEGE5oP3U6oHcPn/baR4cPQIz/hmKySoIn1XRzt20W+97sFXEzZ5rQS9V3bptvTv3/vcKXH6r6srnkO11XyQ0ty/ur90z7/WfE5Znpz+t+n1cAW7Ln3e8+9tjnzBoDIwnR8EoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AYAgCq+cxBACgAAA==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] doesn't exist or is not a regular file".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
    }

    @Test
    public void publishSbomContentDefinitionFileDefinitionFileTarIsDir() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA+3PMQrDMAyFYR3FJ0glbNnHKYEkxdC40KZLT98QumZK6PR/ywMt72kYp9rqUh/tOtX72C39s7t9LnImXRV30axW3LZUte3+I5Zi8mxeUhK1GLNJ8FNX7Hi/1pdDkH6Ya/tHIQAAAAAAAAAAAAAAAAAAx30BmAQDQgAoAAA=",
                SbomContentType.DEFINITION_FILE.getType(),
                "[%s] doesn't exist or is not a regular file".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
    }

    @Test
    public void publishSbomContentTraceDataDefinitionFileTarIsDir() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA+3PMQrDMAyFYR3FJ0glbNnHKYEkxdC40KZLT98QumZK6PR/ywMt72kYp9rqUh/tOtX72C39s7t9LnImXRV30axW3LZUte3+I5Zi8mxeUhK1GLNJ8FNX7Hi/1pdDkH6Ya/tHIQAAAAAAAAAAAAAAAAAAx30BmAQDQgAoAAA=",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] doesn't exist or is not a regular file".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
    }

    @Test
    public void publishSbomContentDefinitionFileDefinitionFileTarCanNotExtract() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA+3PQQqDQAyF4RxlTiCJM84cpwhqCbRTaHXj6RVx2V2lq//bPMjmvQzj5NVnf9Xb5I+xmft3c1/lUrrLKYlmtdLZkap23E9iKaYuW2ljEbXYFpOg1874bvnsL4cg/fD0+o9CAAAAAAAAAAAAAAAAAAB+twEu4Fx6ACgAAA==",
                SbomContentType.DEFINITION_FILE.getType(),
                "Failed to extract [%s]".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
    }

    @Test
    public void publishSbomContentTraceDataDefinitionFileTarCanNotExtract() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA+3PQQqDQAyF4RxlTiCJM84cpwhqCbRTaHXj6RVx2V2lq//bPMjmvQzj5NVnf9Xb5I+xmft3c1/lUrrLKYlmtdLZkap23E9iKaYuW2ljEbXYFpOg1874bvnsL4cg/fD0+o9CAAAAAAAAAAAAAAAAAAB+twEu4Fx6ACgAAA==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "Failed to extract [%s]".formatted(PublishSbomConstants.DEFINITION_FILE_TAR));
    }

    @Test
    public void publishSbomContentDefinitionFileDefinitionFileDirNotExist() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBQ1MzBkMTYxNTM0MzY3MDBgNDY2MDIwYFA+o6AzsoLQZ6WUGBITElNzOPHhYOLiDfzQFhML89t5v3kIMAywXdp1YPwvb5207z4FAwuGA/zZX9hMt7VWVfo8nTLWLvnr23uG/W5ucTtz67WO+6benXicmZye/T++SWzq/XffS3Zm205sa499uP27Mxwqx4UC5/8KH2YgaNgfLjKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFAxHAACM1AuaACgAAA==",
                SbomContentType.DEFINITION_FILE.getType(),
                "[%s] directory doesn't exist or is not a directory".formatted(
                        PublishSbomConstants.DEFINITION_FILE_DIR_NAME));
    }

    @Test
    public void publishSbomContentTraceDataDefinitionFileDirNotExist() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBQ1MzBkMTYxNTM0MzY3MDBgNDY2MDIwYFA+o6AzsoLQZ6WUGBITElNzOPHhYOLiDfzQFhML89t5v3kIMAywXdp1YPwvb5207z4FAwuGA/zZX9hMt7VWVfo8nTLWLvnr23uG/W5ucTtz67WO+6benXicmZye/T++SWzq/XffS3Zm205sa499uP27Mxwqx4UC5/8KH2YgaNgfLjKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFAxHAACM1AuaACgAAA==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] directory doesn't exist or is not a directory".formatted(
                        PublishSbomConstants.DEFINITION_FILE_DIR_NAME));
    }

    @Test
    public void publishSbomContentDefinitionFileDefinitionFileDirNotDir() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBQ3NjBkMTYxNTM0MzE3NzBgNDY2NDQwYFA+o6AzsoLQZ6WUGBITElNzOPHhYOLiDfzQFhML8958jVHMDT8lDmqaziRkO55RxaLF84s97fV4otjS75Wj+78eYZnsdTTPtjXhefqpyi/cJ9R3db1PVbM1eVfYtP+vfBTMcm5IpUr1tX3Kdnx7Ptf60Vedmu+lq2GdW+P+95XUvPXmPQoL9XR8EoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2BYAQDCKZBFACgAAA==",
                SbomContentType.DEFINITION_FILE.getType(),
                "[%s] directory doesn't exist or is not a directory".formatted(
                        PublishSbomConstants.DEFINITION_FILE_DIR_NAME));
    }

    @Test
    public void publishSbomContentTraceDataDefinitionFileDirNotDir() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBQ3NjBkMTYxNTM0MzE3NzBgNDY2NDQwYFA+o6AzsoLQZ6WUGBITElNzOPHhYOLiDfzQFhML8958jVHMDT8lDmqaziRkO55RxaLF84s97fV4otjS75Wj+78eYZnsdTTPtjXhefqpyi/cJ9R3db1PVbM1eVfYtP+vfBTMcm5IpUr1tX3Kdnx7Ptf60Vedmu+lq2GdW+P+95XUvPXmPQoL9XR8EoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2BYAQDCKZBFACgAAA==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] directory doesn't exist or is not a directory".formatted(
                        PublishSbomConstants.DEFINITION_FILE_DIR_NAME));
    }

    @Test
    public void publishSbomContentTraceDataTraceDataTarNotExist() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBoCCDoYmxiamZkYGRIVCdobGRuTGDggF1nYEdlBYDvaygwJCYkpuZRw8LBxeQ7+aAMJjfnnPkanbgaX0ok5p34YjfFwvXAMWE5Rdu/bbu0N6+aPX/2y02ciqHLVw7Ve2emh61sXvCFFX6btHaqOfbfENvf5obUZeWPztqxU7T0qlPwm2Kv/zX/Wuu+rK9fIo1HxOKjQX3uAQ4ueoYNAbAt6NgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwfAAAG3yiYwAoAAA=",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] doesn't exist or is not a regular file".formatted(PublishSbomConstants.TRACE_DATA_TAR));
    }

    @Test
    public void publishSbomContentTraceDataTraceDataTarIsDir() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBoCCDoYmxiamZkYGRIVCdobGRuTGDggF1nYEdlBYDvaygwJCYkpuZRw8LBxeQ7+aAMJjfnnPkanbgaX0ok5p34YjfFwvXAMWE5Rdu/bbu0N6+aPX/2y02ciqHLVw7Ve2emh61sXvCFFX6btHaqOfbfENvf5obUZeWPztqxU7T0qlPwm2Kv/zX/Wuu+rK9fIo1HxOKjQX3uAQ4ueoYNAbAt6MAHZQUJSanxqckliRCs74+9e0A5XFzU1Oc+R8I4PkfSAHzv5GxoSGDgin1nYIJRnj+HwWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFQxsAANXsljMAKAAA",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] doesn't exist or is not a regular file".formatted(PublishSbomConstants.TRACE_DATA_TAR));
    }

    @Test
    public void publishSbomContentTraceDataTraceDataTarCanNotExtract() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBoCCDoYmxiamZkYGRIVCdobGRuTGDggF1nYEdlBYDvaygwJCYkpuZRw8LBxeQ7+aAMJjfnnPkanbgaX0ok5p34YjfFwvXAMWE5Rdu/bbu0N6+aPX/2y02ciqHLVw7Ve2emh61sXvCFFX6btHaqOfbfENvf5obUZeWPztqxU7T0qlPwm2Kv/zX/Wuu+rK9fIo1HxOKjQX3uAQ4ueoYNAbAt6MAHZQUJSanxqckliTSJOuDAaH8DwTw/G9qaAbM/0ZGRqP5fxSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AUjAKCAADQziKZACgAAA==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "Failed to extract [%s]".formatted(PublishSbomConstants.TRACE_DATA_TAR));
    }

    @Test
    public void publishSbomContentTraceDataTraceDataDirNotExist() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBoCCDoYmxiamZkYGRIVCdobGRuTGDggF1nYEdlBYDvaygwJCYkpuZRw8LBxeQ7+aAMJjfnnPkanbgaX0ok5p34YjfFwvXAMWE5Rdu/bbu0N6+aPX/2y02ciqHLVw7Ve2emh61sXvCFFX6btHaqOfbfENvf5obUZeWPztqxU7T0qlPwm2Kv/zX/Wuu+rK9fIo1HxOKjQX3uAQ4ueoYNAbAt6MAHZQUJSanxqckliTSJOuDAcH8b2oOz/9mhubA/G9kZGI0mv/pAZDz/27eQw4CLBd0n1o9uFZR+zVCSbGhwf9/hJisgvDe6T0mJ33mPSqoNV61SN/W/em8vc/v1buee75z2srrM7bVPZl08dWPbMH3z7Nrt4i9flq293+yANyOuu+MKu52vKM5fhSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo4AGAACdzdOjACgAAA==",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] directory doesn't exist or is not a directory".formatted(
                        PublishSbomConstants.TRACE_DATA_DIR_NAME));
    }

    @Test
    public void publishSbomContentTraceDataTraceDataDirNotDir() throws Exception {
        publishSbomContentErrorCommonFunc(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME,
                "H4sIAAAAAAAAA0tJTcvMyyzJzM+LT8vMSdUrSSzSS69ioCowAAIzExMGAzMDQ3NTQzBtYGAIFgcBoCCDoYmxiamZkYGRIVCdobGRuTGDggF1nYEdlBYDvaygwJCYkpuZRw8LBxeQ7+aAMJjfnnPkanbgaX0ok5p34YjfFwvXAMWE5Rdu/bbu0N6+aPX/2y02ciqHLVw7Ve2emh61sXvCFFX6btHaqOfbfENvf5obUZeWPztqxU7T0qlPwm2Kv/zX/Wuu+rK9fIo1HxOKjQX3uAQ4ueoYNAbAt6MAHZQUJSanxqckliTSJOuDAeH8bwDP/+YgcUMjIyPz0fxPD4Cc/w35mh0EnC9anpI76FzW/nhBoMdEJc0TRfUCTqcYlYL+Xo8oSv6u+r4/89y8Msm3i8KCTxx/5u5V90X9c9VqXTbXlpOxzpsXvdarXTt/nrfmtM+vf/47roBq2f7bDOcvqKqOZv1RMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIwC6gEADz4FTAAoAAA=",
                SbomContentType.SBOM_TRACER_DATA.getType(),
                "[%s] directory doesn't exist or is not a directory".formatted(
                        PublishSbomConstants.TRACE_DATA_DIR_NAME));
    }

    private void publishSbomContentErrorCommonFunc(String productName, String sbomContent, String sbomContentType, String errorInfo) throws Exception {
        testCommon.cleanPublishRawSbomData(productName);

        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();
        publishSbomRequest.setProductName(productName);
        publishSbomRequest.setSbomContentType(sbomContentType);
        publishSbomRequest.setSbomContent(sbomContent);

        this.mockMvc
                .perform(post("/sbom-api/publishSbomFile")
                        .content(Mapper.objectMapper.writeValueAsString(publishSbomRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isAccepted())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorInfo").value(errorInfo))
                .andExpect(jsonPath("$.taskId").isEmpty());
    }

    @Test
    @Order(0)
    public void publishSbomContentSuccess() throws Exception {
        testCommon.cleanPublishRawSbomData(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);

        PublishSbomRequest publishSbomRequest = new PublishSbomRequest();
        publishSbomRequest.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        publishSbomRequest.setSbomContentType(SbomContentType.SPDX_2_2_JSON_SBOM.getType());

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
    @Order(1)
    public void getPublishAsyncResult() throws Exception {
        Product product = productRepository.findByName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)
                .orElseThrow(() -> new RuntimeException("can't find %s's product metadata".formatted(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)));

        RawSbom condition = new RawSbom();
        condition.setValueType(SbomContentType.SPDX_2_2_JSON_SBOM.getType());
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

    @Test
    public void addProductNonAddableProductType() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE + "wrong");
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel("4", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("not allowed to add product with type [%s]".formatted(TestConstants.TEST_PRODUCT_TYPE + "wrong")));
    }

    @Test
    public void addProductInvalidProductType() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType("invalidProductType");
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel("4", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string(containsString("invalid productType: %s, valid types:".formatted(req.getProductType()))));
    }

    @Test
    public void addProductExist() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME);
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel("4", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("product [%s] already exists".formatted(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)));
    }

    @Test
    public void addProductInvalidAttrKey() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "new");
        req.setAttribute(Map.of("invalid_attr", new AddProductRequest.ConfigValueLabel("4", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string(containsString("invalid attribute keys, valid keys:")));
    }

    @Test
    public void addProductBlankValue() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "new");
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel(" ", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("there exists blank values or labels in attribute"));
    }

    @Test
    public void addProductLabelOfValueExist() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "new");
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel("4", "5")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("the label of value [4] already exists, it is [4], not [5]"));
    }

    @Test
    public void addProductValueOfLabelExist() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "new");
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel("5", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("the value of label [4] already exists, it is [4], not [5]"));
    }

    @Test
    public void addProductSameAttrProductExist() throws Exception {
        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "new");
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel("4", "4")));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("product with attribute [%s] already exists, its name is [%s]"
                        .formatted(req.getAttribute(), TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME)));
    }

    @Test
    @Transactional
    public void addProductSuccess() throws Exception {
        String productName = TestConstants.PUBLISH_SAMPLE_PRODUCT_NAME + "new";
        String productConfigName = "arg";
        String value = "testValue";
        String label = "testLabel";

        productRepository.deleteByName(productName);
        assertThat(productRepository.findByName(productName).orElse(null)).isNull();

        ProductConfig productConfig = productConfigRepository.findByProductTypeAndName(TestConstants.TEST_PRODUCT_TYPE, productConfigName).orElse(null);
        assertThat(productConfig).isNotNull();
        productConfigValueRepository.deleteByProductConfigIdAndValue(productConfig.getId(), value);
        assertThat(productConfigValueRepository.findByProductTypeAndConfigNameAndValue(
                TestConstants.TEST_PRODUCT_TYPE, productConfigName, value).orElse(null)).isNull();

        AddProductRequest req = new AddProductRequest();
        req.setProductType(TestConstants.TEST_PRODUCT_TYPE);
        req.setProductName(productName);
        req.setAttribute(Map.of("arg", new AddProductRequest.ConfigValueLabel(value, label)));

        this.mockMvc
                .perform(post("/sbom-api/addProduct")
                        .content(Mapper.objectMapper.writeValueAsString(req))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(content().string("Success"));

        assertThat(productRepository.findByName(productName).orElse(null)).isNotNull();
        assertThat(productConfigValueRepository.findByProductTypeAndConfigNameAndValue(
                TestConstants.TEST_PRODUCT_TYPE, productConfigName, value).orElse(null)).isNotNull();

        productRepository.deleteByName(productName);
        assertThat(productRepository.findByName(productName).orElse(null)).isNull();

        productConfigValueRepository.deleteByProductConfigIdAndValue(productConfig.getId(), value);
        assertThat(productConfigValueRepository.findByProductTypeAndConfigNameAndValue(
                TestConstants.TEST_PRODUCT_TYPE, productConfigName, value).orElse(null)).isNull();
    }
}

