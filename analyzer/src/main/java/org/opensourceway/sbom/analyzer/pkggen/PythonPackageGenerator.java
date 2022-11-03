package org.opensourceway.sbom.analyzer.pkggen;

import com.github.packageurl.PackageURL;
import org.ossreviewtoolkit.analyzer.managers.Pip;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.ossreviewtoolkit.model.Identifier;
import org.ossreviewtoolkit.model.Package;
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration;
import org.ossreviewtoolkit.model.config.RepositoryConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component("files.pythonhosted.org")
public class PythonPackageGenerator extends AbstractPackageGenerator {
    private static final Logger logger = LoggerFactory.getLogger(PythonPackageGenerator.class);

    @Override
    public CuratedPackage generatePackage(String host, String path, String url) {
        String pattern = "/.*/(.*)-([\\d.]+).*";
        Matcher matcher = Pattern.compile(pattern).matcher(path);
        if (matcher.matches()) {
            String name = matcher.group(1);
            String version = matcher.group(2);

            Identifier identifier = new Identifier(PackageURL.StandardTypes.PYPI, "", name, version);
            Package pkg = new Pip.Factory().create(
                    new File(System.getProperty("user.dir")), new AnalyzerConfiguration(), new RepositoryConfiguration())
                    .getPackageFromPyPi(identifier);
            logger.info("successfully generated package from pythonhosted for [name: '{}', version: '{}', url: '{}']",
                    name, version, url);
            return new CuratedPackage(pkg, new ArrayList<>());
        }
        return null;
    }
}
