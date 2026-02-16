package com.cybsec.cryptography.encryption.hybrid.impl;

import com.cybsec.cryptography.encryption.hybrid.HybridEncryption;
import com.cybsec.cryptography.encryption.symmetric.impl.AESEncryption;
import com.cybsec.cryptography.helper.transformation.Transformation;
import com.cybsec.cryptography.helper.transformation.symmetric.impl.AESTransformation;
import com.cybsec.cryptography.helper.util.HKDFUtil;
import com.cybsec.cryptography.helper.util.PasswordUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;

import static com.cybsec.cryptography.helper.Constants.*;

public class ECIESEncryption implements HybridEncryption {
    /**
     * Encrypt data using ECIES cryptography.
     * @param data Data to be encrypted
     * @param recipientPublicKey Public key to be used for shared secret key generation
     * @param transformation Transformation enum
     * @return Encrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for encryption in invalid
     * @throws InvalidKeyException thrown when the public key is invalid
     * @throws IllegalBlockSizeException thrown when encryption fails due to incorrect block size
     * @throws BadPaddingException thrown when encryption fails due to incorrect padding
     */
    @Override
    public byte[] encrypt(byte[] data, Key recipientPublicKey, Transformation transformation)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        if (!(recipientPublicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Invalid key used for encryption. EC public key required.");
        }
        // Ephemeral key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(transformation.getAlgorithm());
        kpg.initialize(transformation.getParameterSpec());
        KeyPair ephemeralKeyPair = kpg.generateKeyPair();

        // ECDH (Elliptic Curve Diffie-Hellman key agreement protocol)
        KeyAgreement ka = KeyAgreement.getInstance(transformation.getKeyAgreementAlgorithm());
        ka.init(ephemeralKeyPair.getPrivate());
        ka.doPhase(recipientPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // HKDF → AES key
        byte[] aesKeyBytes = HKDFUtil.deriveKey(
                sharedSecret,
                null,
                ECIES_HKDF_AES_GCM_INFO.getBytes(),
                ECIES_HKDF_AES_GCM_LENGTH
        );
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, DEFAULT_SYMMETRIC_CRYPTOGRAPHY);

        // AES-GCM
        byte[] cipherText = new AESEncryption().encrypt(data, aesKey, AESTransformation.GCM);
        PasswordUtil.wipe(aesKeyBytes);

        // Serialize
        byte[] ephemeralPubKey = ephemeralKeyPair.getPublic().getEncoded();

        //This is how the buffer need to be allocated
        /*
        ByteBuffer buffer = ByteBuffer.allocate(
                4 + ephemeralPubKey.length + iv.length + cipherText.length
        );
        */

        // But since 'byte[] cipherText' has both IV and cipher text as part of the array,
        // separate addition of iv length not needed and is commented above
        // The first allocation is 4 since int always stores 4 bytes (32 bits) of data, and our first entry in the buffer is
        // buffer.putInt(ephemeralPubKey.length), which will be 4 bytes
        ByteBuffer buffer = ByteBuffer.allocate(
                4 + ephemeralPubKey.length + cipherText.length
        );

        buffer.putInt(ephemeralPubKey.length);
        buffer.put(ephemeralPubKey);
        buffer.put(cipherText);
        return buffer.array();
    }
}
