package org.opensourceway.sbom.analyzer.pkggen;

import org.ossreviewtoolkit.model.CuratedPackage;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component("ftp.gnu.org")
public class GnuPackageGenerator extends AbstractPackageGenerator {
    @Override
    public CuratedPackage generatePackage(String host, String path, String url) {
        String pattern = "/.*?/.*?/(.*?)/.*?-(.*)";
        Matcher matcher = Pattern.compile(pattern).matcher(path);
        if (matcher.matches()) {
            String name = matcher.group(1);
            String version = matcher.group(2);

            return newPackage(name, version, url);
        }
        return null;
    }
}
