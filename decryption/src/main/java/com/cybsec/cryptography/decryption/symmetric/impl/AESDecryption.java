package com.cybsec.cryptography.decryption.symmetric.impl;

import com.cybsec.cryptography.decryption.symmetric.SymmetricDecryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static com.cybsec.cryptography.decryption.DecryptionConstants.*;

public class AESDecryption implements SymmetricDecryption {
    /**
     * Decrypt data using IV based AES cryptography.
     * @param data Encrypted data with IV prepended
     * @param aesKey AES key to be used for decryption
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     */
    @Override
    public byte[] decrypt(byte[] data, Key aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return decrypt(data, aesKey, null);
    }

    /**
     * Decrypt data using IV based AES cryptography with auth tag (AAD) (optional) support.
     * @param data Encrypted data with IV prepended and AAD tag (optional)
     * @param aesKey AES key to be used for decryption
     * @param additionalAuthenticatedData Additional auth data for validating auth tag while decryption
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     */
    @Override
    public byte[] decrypt(byte[] data, Key aesKey, byte[] additionalAuthenticatedData)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(aesKey instanceof SecretKey && AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for decryption. AES key required.");
        }
        //data contains IV + cipher
        if (data.length < GCM_IV_LENGTH_BYTES + 1) {
            throw new IllegalArgumentException("Invalid payload passed for decryption");
        }
        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
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
