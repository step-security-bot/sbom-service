package org.opensourceway.sbom.model.cyclonedx;

import com.fasterxml.jackson.annotation.JsonValue;

public enum Algorithm {

    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),
    SHA3_256("SHA3-256"),
    SHA3_383("SHA3-384"),
    SHA3_512("SHA3-512"),
    BLAKE2B_256("BLAKE2b-256"),
    BLAKE2B_384("BLAKE2b-384"),
    BLAKE2B_512("BLAKE2b-512"),
    BLAKE3("BLAKE3");

    private final String alg;

    Algorithm(String alg) {
        this.alg = alg;
    }

    @JsonValue
    public String getAlg() {
        return alg;
    }
}
