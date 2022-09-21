package org.opensourceway.sbom.clients.sonatype;

import org.opensourceway.sbom.clients.sonatype.vo.GAVInfo;

public interface SonatypeClient {
    boolean needRequest();

    GAVInfo getGAVByChecksum(String checksum);

}