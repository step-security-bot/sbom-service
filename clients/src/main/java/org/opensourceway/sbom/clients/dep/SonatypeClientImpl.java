package org.opensourceway.sbom.clients.dep;

import org.opensourceway.sbom.api.checksum.SonatypeClient;
import org.opensourceway.sbom.model.pojo.response.checksum.maven.GAVInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

@Service
public class SonatypeClientImpl implements SonatypeClient {

    @Value("${sonatype.api.url}")
    private String defaultBaseUrl;

    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    private WebClient createWebClient(String defaultBaseUrl) {
        return WebClient.create(defaultBaseUrl);
    }

    @Override
    public GAVInfo getGAVByChecksum(String checksum) {
        WebClient client = createWebClient(defaultBaseUrl);
        Mono<GAVInfo> mono = client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/solrsearch/select").queryParam("q", "1:" + checksum)
                        .build()
                )
                .retrieve()
                .bodyToMono(GAVInfo.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(30)));
        return mono.block();
    }
}
