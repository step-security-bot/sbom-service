package org.opensourceway.sbom.analyzer.pkggen;

import org.ossreviewtoolkit.model.CuratedPackage;


public interface PackageGenerator {
    CuratedPackage generatePackage(String host, String path, String url);
}
