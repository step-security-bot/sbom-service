package org.opensourceway.sbom.model.spdx;

import org.apache.commons.lang3.StringUtils;

public enum FileType {
    APPLICATION,

    ARCHIVE,

    AUDIO,

    BINARY,

    DOCUMENTATION,

    IMAGE,

    OTHER,

    SOURCE,

    SPDX,

    TEXT,

    VIDEO;

    public static FileType findFileType(String fileTypeName) {
        if (StringUtils.isEmpty(fileTypeName)) {
            return null;
        }
        for (FileType fileType : FileType.values()) {
            if (StringUtils.equalsIgnoreCase(fileTypeName, fileType.name())) {
                return fileType;
            }
        }
        return null;
    }
}
