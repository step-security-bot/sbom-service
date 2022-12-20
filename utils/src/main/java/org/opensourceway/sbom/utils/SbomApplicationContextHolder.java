package org.opensourceway.sbom.utils;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.sbom.api.reader.SbomReader;
import org.opensourceway.sbom.api.writer.SbomWriter;
import org.opensourceway.sbom.model.constants.SbomConstants;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

@Component
public class SbomApplicationContextHolder implements ApplicationContextAware {
    private static ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(@NotNull ApplicationContext applicationContext) throws BeansException {
        SbomApplicationContextHolder.applicationContext = applicationContext;
    }

    public static SbomReader getSbomReader(String serviceName) {
        return applicationContext.getBean(serviceName + SbomConstants.READER_NAME, SbomReader.class);
    }

    public static SbomWriter getSbomWriter(String serviceName) {
        return applicationContext.getBean(serviceName + SbomConstants.WRITER_NAME, SbomWriter.class);
    }
}
