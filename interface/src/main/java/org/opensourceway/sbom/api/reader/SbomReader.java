package org.opensourceway.sbom.api.reader;

import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.sbom.SbomDocument;

import java.io.File;
import java.io.IOException;

public interface SbomReader {

    void read(String productName, File file) throws IOException;

    void read(String productName, SbomFormat format, byte[] fileContent) throws IOException;

    SbomDocument readToDocument(String productName, SbomFormat format, byte[] fileContent) throws IOException;

    Sbom persistSbom(String productName, SbomDocument sbomDocument);
}
