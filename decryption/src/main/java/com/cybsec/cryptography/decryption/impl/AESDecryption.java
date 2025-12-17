package com.cybsec.cryptography.decryption.impl;

import com.cybsec.cryptography.decryption.Decryption;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static com.cybsec.cryptography.decryption.DecryptionConstants.*;

public class AESDecryption implements Decryption {
    private byte[] additionalAuthenticatedData;

    /**
     * Decrypt data using IV based AES cryptography with auth tag (AAD) (optional) support.
     * @param data Base64 encoded encrypted data with IV and AAD tag (optional)
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
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        if (!(aesKey instanceof SecretKey && AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm()))) {
            throw new IllegalArgumentException("Invalid key used for decryption. AES key required.");
        }
        byte[] ivAndCipher = Base64.getDecoder().decode(data);
        if (ivAndCipher.length < GCM_IV_LENGTH_BYTES + 1) {
            throw new IllegalArgumentException("Invalid payload passed for decryption");
        }
        ByteBuffer bb = ByteBuffer.wrap(ivAndCipher);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        if (this.additionalAuthenticatedData != null && this.additionalAuthenticatedData.length > 0) {
            cipher.updateAAD(this.additionalAuthenticatedData);
        }
        try {
            return Arrays.toString(cipher.doFinal(cipherText));
        } catch (AEADBadTagException e) {
            throw new SecurityException("Invalid authentication tag (data may have been tampered)", e);
        }
    }

    @Override
    public void setAdditionalAuthenticatedData(String data) {
        this.additionalAuthenticatedData = data.getBytes();
    }
}
