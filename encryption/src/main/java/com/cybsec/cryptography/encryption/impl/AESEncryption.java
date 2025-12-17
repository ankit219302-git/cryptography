package com.cybsec.cryptography.encryption.impl;

import com.cybsec.cryptography.encryption.Encryption;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.cybsec.cryptography.encryption.EncryptionConstants.AES_ALGORITHM;

public class AESEncryption implements Encryption {
    /**
     * Encrypt data using AES cryptography.
     * @param data Data to be encrypted
     * @param aesKey AES key to be used for encryption
     * @return Encrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when encryption fails due to incorrect block size
     * @throws BadPaddingException thrown when encryption fails due to incorrect padding
     */
    @Override
    public String encrypt(String data, Key aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(aesKey instanceof SecretKey && AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for encryption. AES key required.");
        }
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
