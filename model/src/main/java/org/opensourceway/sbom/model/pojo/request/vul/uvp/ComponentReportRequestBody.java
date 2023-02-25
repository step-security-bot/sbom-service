package org.opensourceway.sbom.model.pojo.request.vul.uvp;

import java.io.Serializable;
import java.util.List;

public record ComponentReportRequestBody(List<String> coordinates) implements Serializable {
}

