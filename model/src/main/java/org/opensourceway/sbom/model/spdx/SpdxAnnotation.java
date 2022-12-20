package org.opensourceway.sbom.model.spdx;

public record SpdxAnnotation(
        String annotationDate,
        AnnotationType annotationType,
        String annotator,
        String comment
) {}
