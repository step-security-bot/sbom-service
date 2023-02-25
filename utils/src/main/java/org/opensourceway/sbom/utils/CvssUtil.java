package org.opensourceway.sbom.utils;

import us.springett.cvss.Cvss;

public class CvssUtil {
    public static Double calculateScore(String vector) {
        return Cvss.fromVector(vector).calculateScore().getBaseScore();
    }

}
