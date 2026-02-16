package com.cybsec.cryptography.helper.transformation;

import java.security.spec.AlgorithmParameterSpec;

public interface Transformation {
    String getAlgorithm();

    AlgorithmParameterSpec getParameterSpec();

    default AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        throw new UnsupportedOperationException("Initialization Vector (IV) not supported");
    }

    default int getIvLengthBytes() {
        throw new UnsupportedOperationException("Initialization Vector (IV) not supported");
    }

    default boolean supportsAad() {
        throw new UnsupportedOperationException("Additional Authenticated Data (AAD) not supported");
    }

    default String getKeyAgreementAlgorithm() {
        throw new UnsupportedOperationException("Key agreement algorithm not supported");
    }

    default int getSharedSecretLengthBytes() {
        throw new UnsupportedOperationException("Shared secret not supported");
    }
}
