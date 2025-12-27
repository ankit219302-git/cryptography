package com.cybsec.cryptography.encryption.symmetric;

import com.cybsec.cryptography.encryption.Encryption;
import com.cybsec.cryptography.helper.transformation.Transformation;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface SymmetricEncryption extends Encryption {
    @Override
    byte[] encrypt(byte[] data, Key aesKey, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException;

    @Override
    byte[] encrypt(byte[] data, Key key, byte[] additionalAuthenticatedData, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException;
}
