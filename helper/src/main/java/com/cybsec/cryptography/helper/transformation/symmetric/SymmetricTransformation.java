package com.cybsec.cryptography.helper.transformation.symmetric;

import com.cybsec.cryptography.helper.transformation.Transformation;

import java.security.spec.AlgorithmParameterSpec;

public interface SymmetricTransformation extends Transformation {
    @Override
    String getAlgorithm();

    @Override
    AlgorithmParameterSpec getParameterSpec();

    @Override
    AlgorithmParameterSpec getParameterSpec(byte[] iv);

    @Override
    int getIvLengthBytes();

    @Override
    boolean supportsAad();
}
