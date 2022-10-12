package org.opensourceway.sbom.analyzer.pkggen;

import com.github.packageurl.PackageURL;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.ossreviewtoolkit.model.Hash;
import org.ossreviewtoolkit.model.Identifier;
import org.ossreviewtoolkit.model.Package;
import org.ossreviewtoolkit.model.RemoteArtifact;
import org.ossreviewtoolkit.model.VcsInfo;
import org.ossreviewtoolkit.model.utils.ExtensionsKt;
import org.ossreviewtoolkit.utils.ort.ProcessedDeclaredLicense;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.TreeSet;

public abstract class AbstractPackageGenerator implements PackageGenerator {
    private static final Logger logger = LoggerFactory.getLogger(AbstractPackageGenerator.class);

    protected CuratedPackage newPackage(String name, String version, String url) {
        Identifier identifier = new Identifier(PackageURL.StandardTypes.GENERIC, "", name, version);
        Package pkg = new Package(identifier, ExtensionsKt.toPurl(identifier), "", new TreeSet<>(),
                new TreeSet<>(), ProcessedDeclaredLicense.EMPTY, null, "",
                "", RemoteArtifact.EMPTY, new RemoteArtifact(url, Hash.Companion.getNONE()),
                VcsInfo.EMPTY, VcsInfo.EMPTY, false, false);
        logger.info("successfully generated package for [name: '{}', version: '{}', url: '{}']", name, version, url);
        return new CuratedPackage(pkg, new ArrayList<>());
    }
}
