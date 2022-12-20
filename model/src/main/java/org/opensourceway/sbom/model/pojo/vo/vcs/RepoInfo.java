package org.opensourceway.sbom.model.pojo.vo.vcs;

import java.util.SortedSet;

public record RepoInfo(SortedSet<String> authors, SortedSet<String> licenses, String description, String homepageUrl,
                       String repoUrl) {}
