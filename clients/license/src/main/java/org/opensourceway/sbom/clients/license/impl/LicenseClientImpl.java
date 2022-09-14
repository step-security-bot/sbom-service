package org.opensourceway.sbom.clients.license.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.io.CloseMode;
import org.opensourceway.sbom.clients.license.LicenseClient;
import org.opensourceway.sbom.clients.license.vo.ComplianceResponse;
import org.opensourceway.sbom.clients.license.vo.LicenseInfo;
import org.opensourceway.sbom.clients.license.vo.LicenseNameAndUrl;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class LicenseClientImpl implements LicenseClient {

    private static final Logger logger = LoggerFactory.getLogger(LicenseClientImpl.class);

    @Value("${compliance3.api.url}")
    private String defaultBaseUrl;

    @Value("${opensource.api.url}")
    private String licenseInfoBaseUrl;

    // format the license info from json to map type
    public static Map<String, LicenseNameAndUrl> FormatLicenseInfos(LicenseInfo[] licenseInfos) {
        Map<String, LicenseNameAndUrl> licenseInfoMap = new HashMap<>();

        Arrays.stream(licenseInfos).forEach(licenseInfo -> {
            LicenseNameAndUrl licenseNameAndUrl = new LicenseNameAndUrl();

            licenseNameAndUrl.setName(licenseInfo.getName());
            if (licenseInfo.getText().size() == 0) {
                licenseNameAndUrl.setUrl(null);
            } else {
                licenseNameAndUrl.setUrl(licenseInfo.getText().get(0).getUrl());
            }
            licenseInfoMap.put(licenseInfo.getId(), licenseNameAndUrl);
        });
        return licenseInfoMap;
    }

    private WebClient createWebClient(String defaultBaseUrl) {
        return WebClient.create(defaultBaseUrl);
    }

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    // get licenses from api by purl
    @Override
    public ComplianceResponse[] getComponentReport(List<String> coordinates) throws JsonProcessingException {
        String licenseListStr = Mapper.jsonMapper.writeValueAsString(coordinates);
        WebClient client = createWebClient(defaultBaseUrl);
        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("purl", licenseListStr);

        logger.info("request license:" + Thread.currentThread().getName());

        Mono<ComplianceResponse[]> mono = client.post()
                .uri("/lic")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(builder.build())
                .retrieve()
                .bodyToMono(ComplianceResponse[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));

        ComplianceResponse[] result = mono.block();

        return result;
    }

    // get a json which has the info and url for all the licenses
    @Override
    public Map<String, LicenseNameAndUrl> getLicensesInfo() {
        WebClient client = createWebClient(licenseInfoBaseUrl);
        LicenseInfo[] licenseInfos = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/licenses/licenses.json")
                        .build()
                )
                .retrieve().bodyToMono(LicenseInfo[].class).block();
        return FormatLicenseInfos(licenseInfos);
    }

    // request api to scan the licenses in repo
    @Override
    public void scanLicenseFromPurl(String purl) {
        HttpPost httpPost;
        CloseableHttpClient httpClient = null;
        try {
            httpPost = new HttpPost(defaultBaseUrl + "/doSca");

            RequestConfig config = RequestConfig.custom().setResponseTimeout(100, TimeUnit.MILLISECONDS).build();
            httpPost.setConfig(config);

            MultipartEntityBuilder builder = MultipartEntityBuilder.create();
            builder.addTextBody("url", purl, ContentType.MULTIPART_FORM_DATA);
            httpPost.setEntity(builder.build());

            httpClient = HttpClients.createDefault();

            try {
                CloseableHttpResponse response = httpClient.execute(httpPost);
                if (response.getCode() != HttpStatus.SC_OK) {
                    throw new RuntimeException(IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8));
                }
            } catch (IOException timeoutException) {
                // ignore timeoutException, do not wait for response
            }

        } finally {
            if (httpClient != null) {
                httpClient.close(CloseMode.IMMEDIATE);
            }
        }

    }
}
