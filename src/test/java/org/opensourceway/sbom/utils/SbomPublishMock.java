package org.opensourceway.sbom.utils;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.model.pojo.request.sbom.PublishSbomRequest;
import org.opensourceway.sbom.model.pojo.response.sbom.PublishSbomResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.Serializable;

public class SbomPublishMock {

    private static final Logger logger = LoggerFactory.getLogger(SbomPublishMock.class);

    private static final String REPO_SERVICE_MOCK_SERVICE_URL = "http://127.0.0.1:14441";

    private static final String SBOM_SERVICE_MOCK_SERVICE_URL = "http://127.0.0.1:13331";

    private static final String PUBLISH_SBOM_PRODUCT_NAME = "openEuler-22.03-LTS-aarch64-dvd.iso";

    private static final String ISO_FILE_PATH = "D:\\SBOM\\openEuler\\22.03-LTS\\ISO\\aarch64\\openEuler-22.03-LTS-aarch64-dvd.iso";
    private static final ExchangeStrategies strategies = ExchangeStrategies.builder()
            .codecs(codecs -> codecs.defaultCodecs().maxInMemorySize(40 * 1024 * 1024))
            .build();

    @Test
    @Disabled
    public void mockSbomPublish() {
        logger.info("begin mock SBOM publish");

        WebClient repoClient = WebClient.builder()
                .baseUrl(REPO_SERVICE_MOCK_SERVICE_URL)
                .exchangeStrategies(strategies)
                .build();

        OpenEulerSbomRequest sbomRequest = new OpenEulerSbomRequest(ISO_FILE_PATH);
        Mono<OpenEulerSbomResponse> sbomMono = repoClient.post()
                .uri("/sbom-repo-api/generateOpenEulerSbom")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(sbomRequest)
                .retrieve()
                .bodyToMono(OpenEulerSbomResponse.class);

        OpenEulerSbomResponse sbomResponse = sbomMono.block();
        if (sbomResponse.getSuccess()) {
            logger.info("get SBOM response success, content size:{}", sbomResponse.getSbomContent().length());
        } else {
            Assertions.fail("get SBOM response failed, errorInfo:%s", sbomResponse.getErrorInfo());
        }

        WebClient sbomClient = WebClient.builder()
                .baseUrl(SBOM_SERVICE_MOCK_SERVICE_URL)
                .exchangeStrategies(strategies)
                .build();

        PublishSbomRequest publishRequest = new PublishSbomRequest();
        publishRequest.setProductName(PUBLISH_SBOM_PRODUCT_NAME);
        publishRequest.setSbomContent(sbomResponse.getSbomContent());

        Mono<PublishSbomResponse> publishMono = sbomClient.post()
                .uri("/sbom-api/publishSbomFile")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(publishRequest)
                .retrieve()
                .bodyToMono(PublishSbomResponse.class);

        PublishSbomResponse publishResponse = publishMono.block();
        if (publishResponse.getSuccess()) {
            logger.info("publish SBOM response success, taskId:{}", publishResponse.getTaskId());
        } else {
            Assertions.fail("publish SBOM response failed, errorInfo:%s", publishResponse.getErrorInfo());
        }
        logger.info("finish mock SBOM publish");
    }

}


class OpenEulerSbomRequest implements Serializable {

    private String artifactPath;

    public OpenEulerSbomRequest(String artifactPath) {
        this.artifactPath = artifactPath;
    }

    public String getArtifactPath() {
        return artifactPath;
    }

    public void setArtifactPath(String artifactPath) {
        this.artifactPath = artifactPath;
    }
}


class OpenEulerSbomResponse implements Serializable {

    private String sbomContent;

    private Boolean success;

    private String errorInfo;

    public String getSbomContent() {
        return sbomContent;
    }

    public void setSbomContent(String sbomContent) {
        this.sbomContent = sbomContent;
    }

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public String getErrorInfo() {
        return errorInfo;
    }

    public void setErrorInfo(String errorInfo) {
        this.errorInfo = errorInfo;
    }
}
