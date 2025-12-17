package com.cybsec.cryptography.decryption.impl;

import com.cybsec.cryptography.decryption.Decryption;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.cybsec.cryptography.decryption.DecryptionConstants.AES_ALGORITHM;

public class AESDecryption implements Decryption {
    /**
     * Decrypt data using AES cryptography.
     * @param data Data to be decrypted
     * @param aesKey AES key to be used for decryption
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     */
    @Override
    public String decrypt(String data, Key aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(aesKey instanceof SecretKey && AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for decryption. AES key required.");
        }
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decryptedBytes);
    }
}
