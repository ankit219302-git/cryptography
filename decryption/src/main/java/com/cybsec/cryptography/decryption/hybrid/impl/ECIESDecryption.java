package com.cybsec.cryptography.decryption.hybrid.impl;

import com.cybsec.cryptography.decryption.hybrid.HybridDecryption;
import com.cybsec.cryptography.decryption.symmetric.impl.AESDecryption;
import com.cybsec.cryptography.helper.transformation.Transformation;
import com.cybsec.cryptography.helper.transformation.symmetric.impl.AESTransformation;
import com.cybsec.cryptography.helper.util.HKDFUtil;
import com.cybsec.cryptography.helper.util.PasswordUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static com.cybsec.cryptography.helper.Constants.DEFAULT_SYMMETRIC_CRYPTOGRAPHY;
import static com.cybsec.cryptography.helper.Constants.ECIES_HKDF_AES_GCM_INFO;

public class ECIESDecryption implements HybridDecryption {
    /**
     * Decrypt data using ECIES cryptography.
     * @param data Data to be decrypted
     * @param recipientPrivateKey Private key to be used for shared secret key generation
     * @param transformation Transformation enum
     * @return Decrypted data
     * @throws NoSuchPaddingException thrown when provided transformation to create Cipher instance is incorrect
     * @throws NoSuchAlgorithmException thrown when provided transformation to create Cipher instance is incorrect
     * @throws InvalidAlgorithmParameterException thrown when algorithm specification used for decryption in invalid
     * @throws InvalidKeyException thrown when the private key is invalid
     * @throws IllegalBlockSizeException thrown when decryption fails due to incorrect block size
     * @throws BadPaddingException thrown when decryption fails due to incorrect padding
     * @throws InvalidKeySpecException thrown if the given key specification is inappropriate for the key factory to produce a public key
     */
    @Override
    public byte[] decrypt(byte[] data, Key recipientPrivateKey, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        if (!(recipientPrivateKey instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("Invalid key used for decryption. EC private key required.");
        }
        ByteBuffer buffer = ByteBuffer.wrap(data);

        int ephemeralPubKeyLen = buffer.getInt();
        byte[] ephemeralPubKeyBytes = new byte[ephemeralPubKeyLen];
        buffer.get(ephemeralPubKeyBytes);

        KeyFactory kf = KeyFactory.getInstance(transformation.getAlgorithm());
        ECPublicKey ephemeralPubKey = (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(ephemeralPubKeyBytes));
        byte[] ivPlusCipherText = new byte[buffer.remaining()];
        buffer.get(ivPlusCipherText);

        // ECDH (Elliptic Curve Diffie-Hellman key agreement protocol)
        KeyAgreement ka = KeyAgreement.getInstance(transformation.getKeyAgreementAlgorithm());
        ka.init(recipientPrivateKey);
        ka.doPhase(ephemeralPubKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // HKDF
        byte[] aesKeyBytes = HKDFUtil.deriveKey(
                sharedSecret,
                null,
                ECIES_HKDF_AES_GCM_INFO.getBytes(),
                transformation.getSharedSecretLengthBytes()
        );
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, DEFAULT_SYMMETRIC_CRYPTOGRAPHY);
        PasswordUtil.wipe(aesKeyBytes);

        return new AESDecryption().decrypt(ivPlusCipherText, aesKey, AESTransformation.GCM);
    }
}
