package org.opensourceway.sbom.analyzer.parser;

import org.opensourceway.sbom.model.pojo.vo.analyzer.ProcessIdentifier;
import org.ossreviewtoolkit.model.CuratedPackage;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public interface Parser {
    Set<CuratedPackage> parse(Path workspace, List<ProcessIdentifier> allProcess);
}
