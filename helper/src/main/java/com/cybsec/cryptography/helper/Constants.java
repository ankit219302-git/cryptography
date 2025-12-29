package com.cybsec.cryptography.helper;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class Constants {
    public static final SecureRandom SECURE_RANDOM;
    public static final String DEFAULT_ASYMMETRIC_CRYPTOGRAPHY = "RSA";
    public static final String DEFAULT_SYMMETRIC_CRYPTOGRAPHY = "AES";
    public static final String RSA_OAEP_SHA256_MGF1_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String RSA_OAEP_SHA1_MGF1_ALGORITHM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String RSA_PKCS1_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    public static final String AES_CBC_PKCS5_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final int DEFAULT_AES_KEY_SIZE_BITS = 256;
    public static final int AES_GCM_IV_LENGTH_BYTES = 12; // 96 bits, recommended
    public static final int AES_GCM_AUTH_TAG_LENGTH_BITS = 128; // 128-bit authentication tag
    public static final int AES_CBC_IV_LENGTH_BYTES = 16; // 128 bits
    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private Constants() {}
}
