package org.openeuler.sbom.clients.license.impl;

import org.openeuler.sbom.clients.license.LicenseClient;
import org.openeuler.sbom.clients.license.model.ComponentReport;
import org.openeuler.sbom.clients.license.model.ComponentReportRequestBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;

@Service
public class LicenseClientImpl implements LicenseClient {

    private static final Logger logger = LoggerFactory.getLogger(LicenseClientImpl.class);

    @Value("${license.api.url}")
    private String defaultBaseUrl;

    private WebClient createWebClient() {
        return WebClient.create(defaultBaseUrl);
    }

//    @Value("${license.api.token}")
//    private String token;

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    @Override
    public Mono<ComponentReport[]> getComponentReport(List<String> coordinates) {
        WebClient client = createWebClient();
        ComponentReportRequestBody body = new ComponentReportRequestBody(coordinates);
        return client.post()
                .uri(uriBuilder -> uriBuilder
                        .path("/lic")
                        .queryParam("purl",body.coordinates().toString())
                        .build()
                )

                .contentType(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(ComponentReport[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }

}
