package org.opensourceway.sbom.clients.license.impl;

import org.opensourceway.sbom.clients.license.LicenseClient;
import org.opensourceway.sbom.clients.license.model.ComponentReport;
import org.opensourceway.sbom.clients.license.model.ComponentReportRequestBody;
import org.opensourceway.sbom.clients.license.model.License;
import org.opensourceway.sbom.clients.license.model.LicenseInfo;
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

    @Value("${licenseInfo.api.url}")
    private String licenseInfoBaseUrl;

    private WebClient createWebClient(String defaultBaseUrl) {
        return WebClient.create(defaultBaseUrl);
    }


    @Override
    public boolean needRequest() {
        return StringUtils.hasText(this.defaultBaseUrl);
    }

    @Override
    public Mono<ComponentReport[]> getComponentReport(List<String> coordinates) {
        WebClient client = createWebClient(defaultBaseUrl);
        ComponentReportRequestBody body = new ComponentReportRequestBody(coordinates);
        return client.post()
                .uri(uriBuilder -> uriBuilder
                        .path("/lic")
                        .queryParam("purl", body.coordinates().toString())
                        .build()
                )

                .contentType(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(ComponentReport[].class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }

    @Override
    public Mono<LicenseInfo[]> getLicenseInfo() {
        WebClient client = createWebClient(licenseInfoBaseUrl);
        return client.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/licenses/licenses.json")
                        .build()
                )
                .retrieve().bodyToMono(LicenseInfo[].class);
    }

    @Override
    public Mono<License> scanLicenseFromPurl(String purl) {
        WebClient client = createWebClient(defaultBaseUrl);
        return client.post()
                .uri(uriBuilder -> uriBuilder
                        .path("/doSca")
                        .queryParam("url", purl)
                        .build()
                )

                .contentType(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(License.class);
//                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1)));
    }
}
