package org.opensourceway.sbom.manager.model.spdx;

public record SpdxExternalDocumentReference(
        String externalDocumentId,
        String spdxDocument,
        SpdxChecksum checksum
) {}
