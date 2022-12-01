package org.opensourceway.sbom.manager.service.license;

import org.apache.commons.lang3.tuple.Pair;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.opensourceway.sbom.manager.model.License;
import org.opensourceway.sbom.manager.model.Package;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface LicenseService {

    Integer getBulkRequestSize();

    boolean needRequest();

    List<Pair<Package, License>> extractLicenseForPurlRefChunk(UUID sbomId, List<ExternalPurlRef> externalPurlChunk);

    void persistExternalLicenseRefChunk(Pair<Set<Package>, Set<License>> licenseAndPkgListToSave);

}
