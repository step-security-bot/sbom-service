package org.opensourceway.sbom.api.vul;

import org.opensourceway.sbom.model.pojo.response.vul.cve.ComponentReport;
import reactor.core.publisher.Mono;

import java.util.List;

public interface CveManagerClient {

    boolean needRequest();

    Mono<ComponentReport> getComponentReport(List<String> coordinates);
}
