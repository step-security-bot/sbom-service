package org.opensourceway.sbom.api.checksum;

import org.opensourceway.sbom.model.pojo.response.checksum.maven.GAVInfo;

public interface SonatypeClient {
    boolean needRequest();

    GAVInfo getGAVByChecksum(String checksum);

}