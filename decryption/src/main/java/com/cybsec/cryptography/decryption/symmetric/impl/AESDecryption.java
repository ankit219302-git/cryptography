package com.cybsec.cryptography.decryption.symmetric.impl;

import com.cybsec.cryptography.decryption.symmetric.SymmetricDecryption;
import com.cybsec.cryptography.helper.transformation.Transformation;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import static com.cybsec.cryptography.helper.Constants.DEFAULT_SYMMETRIC_CRYPTOGRAPHY;

public class AESDecryption implements SymmetricDecryption {
    /**
     * Decrypt data using IV based AES cryptography.
     * @param data Encrypted data with IV prepended
     * @param aesKey AES key to be used for decryption
     * @param transformation Transformation enum
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     */
    @Override
    public byte[] decrypt(byte[] data, Key aesKey, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return decrypt(data, aesKey, null, transformation);
    }

    /**
     * Decrypt data using IV based AES cryptography with auth tag (AAD) (optional) support.
     * @param data Encrypted data with IV prepended and AAD tag (optional)
     * @param aesKey AES key to be used for decryption
     * @param additionalAuthenticatedData Additional auth data for validating auth tag while decryption
     * @param transformation Transformation enum
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     */
    @Override
    public byte[] decrypt(byte[] data, Key aesKey, byte[] additionalAuthenticatedData, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(aesKey instanceof SecretKey && DEFAULT_SYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for decryption. AES key required.");
        }
        if (additionalAuthenticatedData != null && !transformation.supportsAad()) {
            throw new IllegalArgumentException("AAD not supported for AES transformation: " + transformation);
        }
        //data contains IV + cipher
        if (data.length < transformation.getIvLengthBytes() + 1) {
            throw new IllegalArgumentException("Invalid payload passed for decryption");
        }
        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] iv = new byte[transformation.getIvLengthBytes()];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        Cipher cipher = Cipher.getInstance(transformation.getAlgorithm());
        AlgorithmParameterSpec spec = transformation.getParameterSpec(iv);
        if (spec != null) {
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
        }
        if (additionalAuthenticatedData != null && additionalAuthenticatedData.length > 0) {
            cipher.updateAAD(additionalAuthenticatedData);
        }
        try {
            return cipher.doFinal(cipherText);
        } catch (AEADBadTagException e) {
            throw new SecurityException("Invalid authentication tag (data may have been tampered)", e);
        }
    }
}
