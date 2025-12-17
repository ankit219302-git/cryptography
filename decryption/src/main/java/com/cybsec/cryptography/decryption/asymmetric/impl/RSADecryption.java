package com.cybsec.cryptography.decryption.asymmetric.impl;

import com.cybsec.cryptography.decryption.asymmetric.AsymmetricDecryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;

import static com.cybsec.cryptography.decryption.DecryptionConstants.RSA_OAEP_ALGORITHM;

public class RSADecryption implements AsymmetricDecryption {
    /**
     * Decrypt data using RSA cryptography.
     * @param data Data to be decrypted
     * @param privateKey Private key to be used for decryption
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     * @throws InvalidKeyException thrown when the private key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     */
    @Override
    public byte[] decrypt(byte[] data, Key privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Invalid key used for decryption. RSA private key required.");
        }
        Cipher cipher = Cipher.getInstance(RSA_OAEP_ALGORITHM);
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        return cipher.doFinal(data);
    }
}
