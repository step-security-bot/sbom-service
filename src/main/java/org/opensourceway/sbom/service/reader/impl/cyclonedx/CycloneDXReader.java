package org.opensourceway.sbom.service.reader.impl.cyclonedx;

import org.opensourceway.sbom.api.reader.SbomReader;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.opensourceway.sbom.model.entity.Sbom;
import org.opensourceway.sbom.model.enums.SbomFormat;
import org.opensourceway.sbom.model.sbom.SbomDocument;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.IOException;

@Service(value = SbomConstants.CYCLONEDX_NAME + SbomConstants.READER_NAME)
@Transactional(rollbackFor = Exception.class)
public class CycloneDXReader implements SbomReader {
    @Override
    public void read(String productName, File file) throws IOException {

    }

    @Override
    public void read(String productName, SbomFormat format, byte[] fileContent) throws IOException {

    }

    @Override
    public SbomDocument readToDocument(String productName, SbomFormat format, byte[] fileContent) throws IOException {
        return null;
    }

    @Override
    public Sbom persistSbom(String productName, SbomDocument sbomDocument) {
        return null;
    }

}
