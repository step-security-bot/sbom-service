package org.opensourceway.sbom.manager.model.spdx;

public record SpdxAnnotation(
        String annotationDate,
        AnnotationType annotationType,
        String annotator,
        String comment
) {}
