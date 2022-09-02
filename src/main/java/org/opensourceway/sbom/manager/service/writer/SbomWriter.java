package org.opensourceway.sbom.manager.service.writer;


import org.opensourceway.sbom.manager.utils.SbomFormat;

import java.io.IOException;

public interface SbomWriter {
    byte[] write(String productName, SbomFormat format) throws IOException;
}
