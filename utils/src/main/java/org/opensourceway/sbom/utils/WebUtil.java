package org.opensourceway.sbom.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class WebUtil {
    @Value("${spring.codec.max-in-memory-size}")
    private String maxInMemorySize;

    public final WebClient createWebClient() {
        return WebClient.builder()
                .exchangeStrategies(customStrategy())
                .build();
    }

    public final WebClient createWebClient(String baseUrl) {
        return WebClient.builder()
                .baseUrl(baseUrl)
                .exchangeStrategies(customStrategy())
                .build();
    }

    private ExchangeStrategies customStrategy() {
        return ExchangeStrategies.builder()
                .codecs(codecs -> codecs.defaultCodecs().maxInMemorySize((int) DataSize.parse(maxInMemorySize).toBytes()))
                .build();
    }
}
