package com.cybsec.cryptography.encryption.hybrid;

import com.cybsec.cryptography.encryption.Encryption;
import com.cybsec.cryptography.helper.transformation.Transformation;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface HybridEncryption extends Encryption {
    @Override
    byte[] encrypt(byte[] data, Key aesKey, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;
}
