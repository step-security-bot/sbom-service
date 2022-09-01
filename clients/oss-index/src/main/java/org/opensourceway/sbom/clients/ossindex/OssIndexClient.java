package org.opensourceway.sbom.clients.ossindex;

import org.opensourceway.sbom.clients.ossindex.model.ComponentReportElement;
import reactor.core.publisher.Mono;

import java.util.List;

public interface OssIndexClient {

    boolean needRequest();

    Mono<ComponentReportElement[]> getComponentReport(List<String> coordinates);
}
