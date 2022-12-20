package org.opensourceway.sbom.utils;

import org.opensourceway.sbom.model.constants.SbomConstants;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class UrlUtil {

    /**
     * example:<a href="http://localhost:8080/#/sbomPackages?productName=openEuler-22.03-LTS-x86_64-dvd.iso">http://localhost:8080/#/sbomPackages?productName=openEuler-22.03-LTS-x86_64-dvd.iso</a>
     */
    public static String generateSbomUrl(String sbomWebsiteDomain, String productName) {
        return SbomConstants.PACKAGE_LIST_PAGE_URL_PATTERN.formatted(
                sbomWebsiteDomain, URLDecoder.decode(productName, StandardCharsets.UTF_8));
    }

}
