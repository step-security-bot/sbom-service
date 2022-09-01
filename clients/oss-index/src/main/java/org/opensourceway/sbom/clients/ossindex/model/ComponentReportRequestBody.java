package org.opensourceway.sbom.clients.ossindex.model;

import java.io.Serializable;
import java.util.List;

public record ComponentReportRequestBody(List<String> coordinates) implements Serializable {}
