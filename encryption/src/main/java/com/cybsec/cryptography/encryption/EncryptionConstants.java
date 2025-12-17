package com.cybsec.cryptography.encryption;

import java.security.SecureRandom;

public final class EncryptionConstants {
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final String RSA_OAEP_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits, recommended
    public static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag

    private EncryptionConstants() {}
}
