package org.opensourceway.sbom.clients.license;

import org.opensourceway.sbom.clients.license.model.ComponentReport;
import reactor.core.publisher.Mono;

import java.util.List;

public interface LicenseClient {

    boolean needRequest();

    Mono<ComponentReport[]> getComponentReport(List<String> coordinates);
}
