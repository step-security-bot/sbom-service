package org.openeuler.sbom.clients.license;

import org.openeuler.sbom.clients.license.model.ComponentReport;
import reactor.core.publisher.Mono;

import java.util.List;

public interface LicenseClient {

    boolean needRequest();

    Mono<ComponentReport[]> getComponentReport(List<String> coordinates);
}
