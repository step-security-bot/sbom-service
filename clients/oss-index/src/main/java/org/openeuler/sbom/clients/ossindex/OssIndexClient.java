package org.openeuler.sbom.clients.ossindex;

import org.openeuler.sbom.clients.ossindex.model.ComponentReportElement;
import reactor.core.publisher.Mono;

import java.util.List;

public interface OssIndexClient {

    boolean needRequest();

    Mono<ComponentReportElement[]> getComponentReport(List<String> coordinates);
}
