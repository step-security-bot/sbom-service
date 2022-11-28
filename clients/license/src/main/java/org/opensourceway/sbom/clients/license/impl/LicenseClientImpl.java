package org.opensourceway.sbom.clients.license.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.opensourceway.sbom.clients.license.vo.LicensesJson;
import org.opensourceway.sbom.utils.Mapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.http.codec.json.Jackson2JsonDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.unit.DataSize;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class LicenseClientImpl implements LicenseClient {

    private static final Logger logger = LoggerFactory.getLogger(LicenseClientImpl.class);

    @Value("${compliance3.api.url}")
    private String defaultBaseUrl;

    @Value("${spdx.license.url}")
    private String licenseInfoBaseUrl;

    @Value("${spring.codec.max-in-memory-size}")
    private String maxInMemorySize;

    private WebClient createWebClient(String defaultBaseUrl) {
        ExchangeStrategies strategies = ExchangeStrategies.builder()
                .codecs(codecs -> codecs.defaultCodecs().maxInMemorySize((int) DataSize.parse(maxInMemorySize).toBytes()))
                .build();
        return WebClient.builder()
                .baseUrl(defaultBaseUrl)
                .exchangeStrategies(strategies)
                .build();
    }

    private WebClient createWebClientForPlainText(String defaultBaseUrl) {
        return WebClient.builder()
                .baseUrl(defaultBaseUrl)
                .exchangeStrategies(ExchangeStrategies.builder().codecs(configurer -> {
                            ObjectMapper mapper = new ObjectMapper();
                            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                            configurer.customCodecs().register(new Jackson2JsonDecoder(
                                    mapper, MimeTypeUtils.parseMimeType(MediaType.TEXT_PLAIN_VALUE)));
                        }).build())
                .build();
    }

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    // get licenses from api by purl
    @Override
    public ComplianceResponse[] getComplianceResponse(List<String> coordinates) throws JsonProcessingException {
        String licenseListStr = Mapper.jsonMapper.writeValueAsString(coordinates);
        WebClient client = createWebClient(defaultBaseUrl);
        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("purl", licenseListStr);

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
    public Map<String, LicenseInfo> getLicensesInfo() {
        WebClient client = createWebClientForPlainText(licenseInfoBaseUrl);
        LicensesJson licensesJson = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/spdx/license-list-data/master/json/licenses.json")
                        .build()
                )
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(LicensesJson.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)))
                .block();
        return ObjectUtils.isEmpty(licensesJson) ? Map.of() :
                licensesJson.getLicenses().stream().collect(Collectors.toMap(LicenseInfo::getLicenseId, Function.identity()));
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
