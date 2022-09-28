package org.opensourceway.sbom.utils;

import org.springframework.web.reactive.function.client.WebClientResponseException;

public class WebClientExceptionFilter {

    public static boolean is5xxException(Throwable th) {
        if (th instanceof WebClientResponseException ex) {
            return ex.getRawStatusCode() > 499 && ex.getRawStatusCode() < 600;
        }
        return false;
    }
}
