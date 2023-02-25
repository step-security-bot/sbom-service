package org.opensourceway.sbom.api.vul;

import org.opensourceway.sbom.model.pojo.response.vul.uvp.UvpVulnerabilityReport;
import reactor.core.publisher.Mono;

import java.util.List;

public interface UvpClient {
    boolean needRequest();

    Mono<UvpVulnerabilityReport[]> getComponentReport(List<String> coordinates);
}
