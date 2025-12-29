package com.cybsec.cryptography.decryption.asymmetric.impl;

import com.cybsec.cryptography.decryption.asymmetric.AsymmetricDecryption;
import com.cybsec.cryptography.helper.transformation.Transformation;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;

public class RSADecryption implements AsymmetricDecryption {
    /**
     * Decrypt data using RSA cryptography.
     * @param data Data to be decrypted
     * @param privateKey Private key to be used for decryption
     * @param transformation Transformation enum
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     * @throws InvalidKeyException thrown when the private key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     */
    @Override
    public byte[] decrypt(byte[] data, Key privateKey, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Invalid key used for decryption. RSA private key required.");
        }
        Cipher cipher = Cipher.getInstance(transformation.getAlgorithm());
        if (transformation.getParameterSpec() != null) {
            cipher.init(Cipher.DECRYPT_MODE, privateKey, transformation.getParameterSpec());
        } else {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        }
        return cipher.doFinal(data);
    }
}
