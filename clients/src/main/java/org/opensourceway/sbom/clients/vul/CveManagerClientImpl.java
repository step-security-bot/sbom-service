package org.opensourceway.sbom.clients.vul;

import org.opensourceway.sbom.api.vul.CveManagerClient;
import org.opensourceway.sbom.model.pojo.request.vul.cve.ComponentReportRequestBody;
import org.opensourceway.sbom.model.pojo.response.vul.cve.ComponentReport;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.util.unit.DataSize;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;

@Service
public class CveManagerClientImpl implements CveManagerClient {

    @Value("${cve-manager.api.url}")
    private String defaultBaseUrl;

    @Value("${spring.codec.max-in-memory-size}")
    private String maxInMemorySize;

    private WebClient createWebClient() {
        ExchangeStrategies strategies = ExchangeStrategies.builder()
                .codecs(codecs -> codecs.defaultCodecs().maxInMemorySize((int) DataSize.parse(maxInMemorySize).toBytes()))
                .build();
        return WebClient.builder()
                .baseUrl(this.defaultBaseUrl)
                .exchangeStrategies(strategies)
                .build();
    }

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    @Override
    public Mono<ComponentReport> getComponentReport(List<String> coordinates) {
        WebClient client = createWebClient();
        ComponentReportRequestBody body = new ComponentReportRequestBody(coordinates);
        return client.post()
                .uri("/cve-manager/v1/cve/detail/sbom")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(ComponentReport.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }

}

