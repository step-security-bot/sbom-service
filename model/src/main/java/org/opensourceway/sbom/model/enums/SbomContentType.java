package org.opensourceway.sbom.model.enums;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

@JsonClassDescription
public enum SbomContentType {
    SPDX_2_2_JSON_SBOM("spdx_2.2_json_sbom"),

    SBOM_TRACER_DATA("sbom_tracer_data"),

    DEFINITION_FILE("definition_file");

    private final String type;

    SbomContentType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public static boolean isValidType(String type) {
        return Arrays.stream(SbomContentType.values())
                .map(SbomContentType::getType)
                .toList().contains(type);
    }

    public static SbomContentType findByType(String type) {
        for (SbomContentType sbomContentType : SbomContentType.values()) {
            if (StringUtils.equals(type, sbomContentType.getType())) {
                return sbomContentType;
            }
        }
        throw new RuntimeException("Invalid sbomContentType: %s, allowed types: %s".formatted(type,
                Arrays.stream(SbomContentType.values()).map(SbomContentType::getType).toList()));
    }

    public static SbomSpecification getSpecByType(String type) {
        return SbomSpecification.SPDX_2_2;
    }

    public static SbomFormat getFormatByType(String type) {
        return SbomFormat.JSON;
    }

    public static SbomContentType findBySpecAndFormat(SbomSpecification spec, SbomFormat format) {
        if (SbomSpecification.SPDX_2_2.equals(spec) && SbomFormat.JSON.equals(format)) {
            return SbomContentType.SPDX_2_2_JSON_SBOM;
        }
        throw new RuntimeException("unsupported spec and format: %s, %s".formatted(spec, format));
    }
}
