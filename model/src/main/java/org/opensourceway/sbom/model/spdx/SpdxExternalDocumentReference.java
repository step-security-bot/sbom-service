package org.opensourceway.sbom.model.spdx;

public record SpdxExternalDocumentReference(
        String externalDocumentId,
        String spdxDocument,
        SpdxChecksum checksum
) {}
