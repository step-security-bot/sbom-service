package org.openeuler.sbom.clients.license.model;

import java.io.Serializable;
import java.util.List;

public record ComponentReportRequestBody(List<String> coordinates) implements Serializable {}
