package org.opensourceway.sbom.api.vul;

import org.opensourceway.sbom.model.pojo.response.vul.ossindex.ComponentReportElement;
import reactor.core.publisher.Mono;

import java.util.List;

public interface OssIndexClient {

    boolean needRequest();

    Mono<ComponentReportElement[]> getComponentReport(List<String> coordinates);
}
