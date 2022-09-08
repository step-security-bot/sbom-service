package org.opensourceway.sbom.constants;

import java.util.Arrays;
import java.util.List;

public class SbomConstants {
    public static final String READER_NAME = "reader";
    public static final String WRITER_NAME = "writer";

    public static final String SPDX_NAME = "SPDX";
    public static final String CYCLONEDX_NAME = "CycloneDX";
    public static final String SWID_NAME = "SWID";

    public static final int MAX_QUERY_LINE = 15;

    public static final List<String> ALLOW_ORIGINS = Arrays.asList("http://localhost:8080", "http://127.0.0.1:8080");

    public static final String PURL_SCHEMA_DEFAULT = "pkg";

    public static final String PURL_MAVEN_TYPE_VALUE = "maven";

    public static final String PURL_RPM_TYPE_VALUE = "rpm";

    // task status of wait to run
    public static final String TASK_STATUS_WAIT = "WAIT";

    // task status of running
    public static final String TASK_STATUS_RUNNING = "RUNNING";

    // task status of finish parse sbom metadata, goto extract consume info
    public static final String TASK_STATUS_FINISH_PARSE = "FINISH_PARSE";

    // task status of finish all import sbom steps
    public static final String TASK_STATUS_FINISH = "FINISH";

    // task status of import sbom failed, and wait to restart
    public static final String TASK_STATUS_FAILED = "FAILED";

    // task status of import sbom failed finally
    public static final String TASK_STATUS_FAILED_FINISH = "FAILED_FINISH";

    public static final String TASK_STATUS_NOT_EXISTS = "task not exists";

    public static final String PACKAGE_LIST_PAGE_URL_PATTERN = "%s/#/sbomPackages?productName=%s";

    public static final String PRODUCT_OPENEULER_NAME = "openEuler";

    public static final String PRODUCT_MINDSPORE_NAME = "MindSpore";

    public static final String PRODUCT_OPENGAUSS_NAME = "openGauss";

}
