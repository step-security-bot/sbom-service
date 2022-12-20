package org.opensourceway.sbom.model.spdx;

import org.apache.commons.lang3.StringUtils;

import java.util.List;

public enum ReferenceCategory {
    SECURITY,

    PACKAGE_MANAGER,

    PROVIDE_MANAGER,

    EXTERNAL_MANAGER,

    RELATIONSHIP_MANAGER,

    PERSISTENT_ID,

    SOURCE_MANAGER,

    OTHER;

    public static final List<ReferenceCategory> BINARY_TYPE = List.of(
            ReferenceCategory.PACKAGE_MANAGER,
            ReferenceCategory.PROVIDE_MANAGER,
            ReferenceCategory.EXTERNAL_MANAGER,
            ReferenceCategory.RELATIONSHIP_MANAGER,
            ReferenceCategory.SOURCE_MANAGER
    );

    public static final List<String> COORDINATES_TYPE_NAME_LIST = List.of(
            ReferenceCategory.PACKAGE_MANAGER.name(),
            ReferenceCategory.PROVIDE_MANAGER.name(),
            ReferenceCategory.EXTERNAL_MANAGER.name()
    );

    public static ReferenceCategory findReferenceCategory(String categoryStr) {
        if (StringUtils.isEmpty(categoryStr)) {
            return null;
        }
        for (ReferenceCategory category : ReferenceCategory.values()) {
            if (StringUtils.equalsIgnoreCase(categoryStr, category.name())) {
                return category;
            }
        }
        return null;
    }
}
