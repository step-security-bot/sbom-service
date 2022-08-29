package org.openeuler.sbom.manager.service.reader.impl.cyclonedx;

import org.opensourceway.sbom.constants.SbomConstants;
import org.openeuler.sbom.manager.service.reader.SbomReader;
import org.openeuler.sbom.manager.utils.SbomFormat;
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
}
