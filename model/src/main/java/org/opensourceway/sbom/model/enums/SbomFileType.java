package org.opensourceway.sbom.model.enums;

import com.fasterxml.jackson.annotation.JsonClassDescription;


@JsonClassDescription
public enum SbomFileType {

    SOURCE,

    BINARY,

    ARCHIVE,

    DOCUMENTATION,

    APPLICATION,

    VIDEO,

    SPDX,

    IMAGE,

    TEXT,

    AUDIO,

    OTHER
}
