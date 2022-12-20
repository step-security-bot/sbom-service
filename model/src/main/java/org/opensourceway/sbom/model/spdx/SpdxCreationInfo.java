package org.opensourceway.sbom.model.spdx;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

public record SpdxCreationInfo(
        @JsonInclude(JsonInclude.Include.NON_EMPTY) String comment,
        String created,
        List <String> creators,
        @JsonInclude(JsonInclude.Include.NON_EMPTY) String licenseListVersion
) {}
