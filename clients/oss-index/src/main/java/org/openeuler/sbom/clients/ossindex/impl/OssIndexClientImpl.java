package org.openeuler.sbom.clients.ossindex.impl;

import org.openeuler.sbom.clients.ossindex.OssIndexClient;
import org.openeuler.sbom.clients.ossindex.model.ComponentReportElement;
import org.openeuler.sbom.clients.ossindex.model.ComponentReportRequestBody;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.text.MessageFormat;
import java.time.Duration;
import java.util.List;

@Service
public class OssIndexClientImpl implements OssIndexClient {

    private static final Logger logger = LoggerFactory.getLogger(OssIndexClientImpl.class);

    @Value("${ossindex.api.url}")
    private String defaultBaseUrl;

    private WebClient createWebClient() {
        return WebClient.create(defaultBaseUrl);
    }

    @Value("${ossindex.api.token}")
    private String token;

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl) && StringUtils.hasText(this.token);
    }

    @Override
    public Mono<ComponentReportElement[]> getComponentReport(List<String> coordinates) {
        WebClient client = createWebClient();
        ComponentReportRequestBody body = new ComponentReportRequestBody(coordinates);
        if (ObjectUtils.isEmpty(token)) {
            return client.post()
                    .uri("/api/v3/component-report")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(ComponentReportElement[].class)
                    .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                            .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                    .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
        }

        return client.post()
                .uri("/api/v3/authorized/component-report")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", MessageFormat.format("Basic {0}", token))
                .bodyValue(body)
                .retrieve()
                .bodyToMono(ComponentReportElement[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(10))
                        .filter(throwable -> throwable instanceof WebClientResponseException.TooManyRequests))
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }
}
