package org.openeuler.sbom.manager.model.spdx;

import java.time.Instant;

public record SpdxAnnotation(
        String annotationDate,
        AnnotationType annotationType,
        String annotator,
        String comment
) {}
