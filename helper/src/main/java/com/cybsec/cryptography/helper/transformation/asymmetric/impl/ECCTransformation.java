package com.cybsec.cryptography.helper.transformation.asymmetric.impl;

import com.cybsec.cryptography.helper.transformation.asymmetric.AsymmetricTransformation;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public enum ECCTransformation implements AsymmetricTransformation {
    /**
     * National Institute of Standards and Technology 256-bit elliptic curve [NIST P-256 (secp256r1)]
     * Widely supported, default in Java.
     */
    P256(
            "EC",
            new ECGenParameterSpec("secp256r1"),
            "ECDH", // Elliptic Curve Diffie-Hellman key agreement protocol
            32
    ),

    /**
     * National Institute of Standards and Technology 384-bit elliptic curve [NIST P-384 (secp384r1)]
     * Higher security margin but slower.
     */
    P384(
            "EC",
            new ECGenParameterSpec("secp384r1"),
            "ECDH", // Elliptic Curve Diffie-Hellman key agreement protocol
            48
    );

    private final String keyAlgorithm;
    private final ECGenParameterSpec curveSpec;
    private final String keyAgreementAlgorithm;
    private final int sharedSecretLengthBytes;

    ECCTransformation(
            String keyAlgorithm,
            ECGenParameterSpec curveSpec,
            String keyAgreementAlgorithm,
            int sharedSecretLengthBytes
    ) {
        this.keyAlgorithm = keyAlgorithm;
        this.curveSpec = curveSpec;
        this.keyAgreementAlgorithm = keyAgreementAlgorithm;
        this.sharedSecretLengthBytes = sharedSecretLengthBytes;
    }

    @Override
    public String getAlgorithm() {
        return this.keyAlgorithm;
    }

    @Override
    public AlgorithmParameterSpec getParameterSpec() {
        return this.curveSpec;
    }

    @Override
    public String getKeyAgreementAlgorithm() {
        return this.keyAgreementAlgorithm;
    }

    @Override
    public int getSharedSecretLengthBytes() {
        return this.sharedSecretLengthBytes;
    }
}
