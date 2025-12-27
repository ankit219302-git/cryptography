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
}
