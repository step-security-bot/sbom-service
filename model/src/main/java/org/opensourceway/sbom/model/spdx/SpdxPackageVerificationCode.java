package org.opensourceway.sbom.model.spdx;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

public record SpdxPackageVerificationCode(
        @JsonInclude(JsonInclude.Include.NON_EMPTY)List<String> packageVerificationCodeExcludedFiles,
        String packageVerificationCodeValue
) {}
