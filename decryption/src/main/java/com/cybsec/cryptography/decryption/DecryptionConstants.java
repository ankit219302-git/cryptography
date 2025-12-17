package com.cybsec.cryptography.decryption;

public final class DecryptionConstants {
    public static final String RSA_OAEP_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits, recommended
    public static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag

    private DecryptionConstants() {}
}
