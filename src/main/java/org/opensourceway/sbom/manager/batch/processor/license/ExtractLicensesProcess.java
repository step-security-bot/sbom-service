package org.opensourceway.sbom.manager.batch.processor.license;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.manager.model.ExternalPurlRef;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.lang.Nullable;

public class ExtractLicensesProcess implements ItemProcessor<ExternalPurlRef, ExternalPurlRef> {

    @Nullable
    @Override
    public ExternalPurlRef process(@NotNull ExternalPurlRef item) {
        return null;
    }

}