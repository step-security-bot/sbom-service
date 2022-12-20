package org.opensourceway.sbom.model.spdx;

public record SpdxChecksum(
        Algorithm algorithm,
        String checksumValue
) {}
