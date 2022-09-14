package org.opensourceway.sbom.utils;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtil {
    public static PackageURL parsePurlFromRepoUrl(String url) {
        for (String suffix : Arrays.asList(".tar.gz", ".tgz", ".tar.xz", ".zip", ".tar", ".gz", ".xz", ".tar.bz2", ".tbz2")) {
            url = url.replace(suffix, "");
        }

        String dirPattern = "https://(.*?)\\..*?/(.*?)/(.*?)/.*/(\\D*([.\\-_\\da-zA-Z]*))/.*";
        String packagePattern = "https://(.*?)\\..*?/(.*?)/(.*?)/.*/(\\D*([.\\-_\\da-zA-Z]*))";
        for (String pattern : Arrays.asList(dirPattern, packagePattern)) {
            Matcher matcher = Pattern.compile(pattern).matcher(url);
            if (matcher.matches()) {
                String host = matcher.group(1);
                String org = matcher.group(2);
                String repo = matcher.group(3);
                String tag = matcher.group(4);
                if (Pattern.compile("[a-zA-Z]*").matcher(tag).matches()) {
                    continue;
                }
                try {
                    return new PackageURL(host, org, repo, tag, null, null);
                } catch (MalformedPackageURLException ignored) {

                }
            }
        }
        return null;
    }
}
