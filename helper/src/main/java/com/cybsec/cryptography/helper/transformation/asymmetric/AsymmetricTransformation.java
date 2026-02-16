package com.cybsec.cryptography.helper.transformation.asymmetric;

import com.cybsec.cryptography.helper.transformation.Transformation;

import java.security.spec.AlgorithmParameterSpec;

public interface AsymmetricTransformation extends Transformation {
    @Override
    String getAlgorithm();

    @Override
    AlgorithmParameterSpec getParameterSpec();

    @Override
    String getKeyAgreementAlgorithm();

    @Override
    int getSharedSecretLengthBytes();
}
