package com.cybsec.cryptography.encryption.symmetric.impl;

import com.cybsec.cryptography.encryption.symmetric.SymmetricEncryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static com.cybsec.cryptography.encryption.EncryptionConstants.*;

public class AESEncryption implements SymmetricEncryption {
    /**
     * Encrypt data using IV based AES cryptography.
     * @param data Data to be encrypted
     * @param aesKey AES key to be used for encryption
     * @return Encrypted data with IV prepended
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when encryption fails due to incorrect block size
     * @throws BadPaddingException thrown when encryption fails due to incorrect padding
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for encryption in invalid
     */
    @Override
    public byte[] encrypt(byte[] data, Key aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return encrypt(data, aesKey, null);
    }

    /**
     * Encrypt data using IV based AES cryptography with auth tag (AAD) (optional) support.
     * @param data Data to be encrypted
     * @param aesKey AES key to be used for encryption
     * @param additionalAuthenticatedData Additional auth data for adding auth tag to encryption
     * @return Encrypted data with IV prepended and AAD tag (optional)
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when encryption fails due to incorrect block size
     * @throws BadPaddingException thrown when encryption fails due to incorrect padding
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for encryption in invalid
     */
    @Override
    public byte[] encrypt(byte[] data, Key aesKey, byte[] additionalAuthenticatedData)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        if (!(aesKey instanceof SecretKey && AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for encryption. AES key required.");
        }
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv); // random nonce
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        if (additionalAuthenticatedData != null && additionalAuthenticatedData.length > 0) {
            cipher.updateAAD(additionalAuthenticatedData);
        }
        byte[] cipherText = cipher.doFinal(data);
        // Prepend IV for transport: IV + (ciphertext + AAD auth tag (if present))
        ByteBuffer finalCipher = ByteBuffer.allocate(iv.length + cipherText.length);
        finalCipher.put(iv);
        finalCipher.put(cipherText);
        return finalCipher.array();
    }
}
