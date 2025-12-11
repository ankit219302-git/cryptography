package com.cybsec.cryptography.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface Encryption {
    String RSA_OAEP_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    String AES_ALGORITHM = "AES";
    String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    int GCM_IV_LENGTH_BYTES = 12; // 96 bits, recommended
    int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag
    int AES_KEY_SIZE_BITS = 256; // 256-bit key

    String encrypt(String data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException;
}
