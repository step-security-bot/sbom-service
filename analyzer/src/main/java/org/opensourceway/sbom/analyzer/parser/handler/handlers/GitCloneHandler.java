package org.opensourceway.sbom.analyzer.parser.handler.handlers;

import org.opensourceway.sbom.analyzer.parser.handler.Handler;
import org.opensourceway.sbom.analyzer.parser.handler.HandlerEnum;
import org.ossreviewtoolkit.model.CuratedPackage;
import org.springframework.stereotype.Component;

@Component("git_clone")
public class GitCloneHandler extends BaseGitHandler implements Handler {
    private final HandlerEnum handlerType = HandlerEnum.GIT_CLONE;

    @Override
    public CuratedPackage handle(String recordJson) {
        return handle(recordJson, handlerType);
    }
}
