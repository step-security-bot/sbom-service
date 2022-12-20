package org.opensourceway.sbom.model.enums;

import com.fasterxml.jackson.annotation.JsonClassDescription;

import java.util.Map;

@JsonClassDescription
public enum SbomFormat {
    JSON("json"),
    YAML("yaml"),
    XML("xml"),
    RDF("rdf");

    private final String fileExtName;

    SbomFormat(String fileExtName) {
        this.fileExtName = fileExtName;
    }

    public String getFileExtName() {
        return fileExtName;
    }

    public static final Map<String, SbomFormat> EXT_TO_FORMAT = Map.of(
            "json", SbomFormat.JSON,
            "yml", SbomFormat.YAML,
            "yaml", SbomFormat.YAML,
            "xml", SbomFormat.XML,
            "rdf", SbomFormat.RDF,
            "rdf.xml", SbomFormat.RDF
    );


    public static SbomFormat findSbomFormat(String fileExt) {
        if (!SbomFormat.EXT_TO_FORMAT.containsKey(fileExt)) {
            throw new RuntimeException("invalid sbom file: %s".formatted(fileExt));
        }

        return SbomFormat.EXT_TO_FORMAT.get(fileExt);
    }
}
