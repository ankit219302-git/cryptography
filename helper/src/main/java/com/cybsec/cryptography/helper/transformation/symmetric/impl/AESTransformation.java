package com.cybsec.cryptography.helper.transformation.symmetric.impl;

import com.cybsec.cryptography.helper.transformation.symmetric.SymmetricTransformation;
import com.cybsec.cryptography.helper.util.PasswordUtil;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

import static com.cybsec.cryptography.helper.Constants.*;

public enum AESTransformation implements SymmetricTransformation {
    /**
     * AES-GCM with 96-bit IV and 128-bit authentication tag.
     * RECOMMENDED for all new cryptography.
     */
    GCM(
            AES_GCM_ALGORITHM,
            AES_GCM_IV_LENGTH_BYTES,
            AES_GCM_AUTH_TAG_LENGTH_BITS,
            true
    ),
    /**
     * AES-CBC with PKCS5 padding.
     * Encryption/decryption ONLY — provides no integrity.
     * Use ONLY for legacy compatibility.
     */
    CBC_PKCS5(
            AES_CBC_PKCS5_ALGORITHM,
            AES_CBC_IV_LENGTH_BYTES,
            -1,   // No auth tag
            false   // AAD not supported
    );

    private final String algorithm;
    private final int ivLengthBytes;
    private final int authTagBits;
    private final boolean supportsAad;

    AESTransformation(String algorithm, int ivLengthBytes, int authTagBits, boolean supportsAad) {
        this.algorithm = algorithm;
        this.ivLengthBytes = ivLengthBytes;
        this.authTagBits = authTagBits;
        this.supportsAad = supportsAad;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public AlgorithmParameterSpec getParameterSpec() {
        return getParameterSpec(null);
    }

    /**
     * Build AlgorithmParameterSpec for this AES mode.
     * Currently only needed for AEAD modes like GCM.
     */
    @Override
    public AlgorithmParameterSpec getParameterSpec(byte[] iv) {
        if (this == GCM) {
            validateIv(iv);
            return new GCMParameterSpec(this.authTagBits, iv);
        }
        if (this == CBC_PKCS5) {
            validateIv(iv);
            return new IvParameterSpec(iv);
        }
        return null;
    }

    @Override
    public int getIvLengthBytes() {
        return this.ivLengthBytes;
    }

    @Override
    public boolean supportsAad() {
        return this.supportsAad;
    }

    private void validateIv(byte[] iv) {
        if (PasswordUtil.isEmpty(iv)) {
            throw new IllegalArgumentException("Initialization Vector (IV) cannot be null/empty");
        }
    }
}
