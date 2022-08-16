package org.openeuler.sbom.manager.service.writer;


import org.openeuler.sbom.manager.utils.SbomFormat;

import java.io.IOException;

public interface SbomWriter {
    byte[] write(String productName, SbomFormat format) throws IOException;
}
