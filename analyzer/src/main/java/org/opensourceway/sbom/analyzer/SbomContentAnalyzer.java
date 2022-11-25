package org.opensourceway.sbom.analyzer;

import java.io.InputStream;

public interface SbomContentAnalyzer {
    byte[] analyze(String productName, InputStream inputStream);
}
