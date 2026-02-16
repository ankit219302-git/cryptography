package com.cybsec.cryptography.helper.transformation.asymmetric.impl;

import com.cybsec.cryptography.helper.transformation.asymmetric.AsymmetricTransformation;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import static com.cybsec.cryptography.helper.Constants.*;

public enum RSATransformation implements AsymmetricTransformation {
    OAEP_SHA256_MGF1(
            RSA_OAEP_SHA256_MGF1_ALGORITHM,
            new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            )
    ),
    OAEP_SHA1_MGF1(
            RSA_OAEP_SHA1_MGF1_ALGORITHM,
            new OAEPParameterSpec(
                    "SHA-1",
                    "MGF1",
                    MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT
            )
    ),
    PKCS1(
            RSA_PKCS1_ALGORITHM,
            null
    );

    private final String algorithm;
    private final AlgorithmParameterSpec parameterSpec;

    RSATransformation(String algorithm, AlgorithmParameterSpec parameterSpec) {
        this.algorithm = algorithm;
        this.parameterSpec = parameterSpec;
    }


    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public AlgorithmParameterSpec getParameterSpec() {
        return this.parameterSpec;
    }

    @Override
    public String getKeyAgreementAlgorithm() {
        throw new UnsupportedOperationException("Key agreement algorithm not supported");
    }

    @Override
    public int getSharedSecretLengthBytes() {
        throw new UnsupportedOperationException("Shared secret not supported");
    }
}
