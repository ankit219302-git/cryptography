package com.cybsec.cryptography.encryption.asymmetric.impl;

import com.cybsec.cryptography.encryption.asymmetric.AsymmetricEncryption;

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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;

import static com.cybsec.cryptography.encryption.EncryptionConstants.RSA_OAEP_ALGORITHM;

public class RSAEncryption implements AsymmetricEncryption {
    /**
     * Encrypt data using RSA cryptography.
     * @param data Data to be encrypted
     * @param publicKey Public key to be used for encryption
     * @return Encrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for encryption in invalid
     * @throws InvalidKeyException thrown when the public key is invalid
     * @throws IllegalBlockSizeException thrown when encryption fails due to incorrect block size
     * @throws BadPaddingException thrown when encryption fails due to incorrect padding
     */
    @Override
    public byte[] encrypt(byte[] data, Key publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Invalid key used for encryption. RSA public key required.");
        }
        Cipher cipher = Cipher.getInstance(RSA_OAEP_ALGORITHM);
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
        return cipher.doFinal(data);
    }
}
