package com.cybsec.cryptography.encryption.impl;

import com.cybsec.cryptography.encryption.Encryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.cybsec.cryptography.encryption.EncryptionConstants.*;

public class AESEncryption implements Encryption {
    private byte[] additionalAuthenticatedData;

    /**
     * Encrypt data using IV based AES cryptography with auth tag (AAD) (optional) support.
     * @param data Data to be encrypted
     * @param aesKey AES key to be used for encryption
     * @return Encrypted data with IV and AAD tag (optional)
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidKeyException thrown when the AES key is invalid
     * @throws IllegalBlockSizeException thrown when encryption fails due to incorrect block size
     * @throws BadPaddingException thrown when encryption fails due to incorrect padding
     */
    @Override
    public String encrypt(String data, Key aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (!(aesKey instanceof SecretKey && AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for encryption. AES key required.");
        }
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv); // random nonce
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        if (this.additionalAuthenticatedData != null && this.additionalAuthenticatedData.length > 0) {
            cipher.updateAAD(this.additionalAuthenticatedData);
        }
        byte[] cipherText = cipher.doFinal(data.getBytes());
        // Prepend IV for transport: IV + (ciphertext + AAD auth tag)
        ByteBuffer bb = ByteBuffer.allocate(iv.length + cipherText.length);
        bb.put(iv);
        bb.put(cipherText);
        byte[] finalCipher = bb.array();
        return Base64.getEncoder().encodeToString(finalCipher);
    }

    @Override
    public void setAdditionalAuthenticatedData(String data) {
        this.additionalAuthenticatedData = data.getBytes();
    }
}
