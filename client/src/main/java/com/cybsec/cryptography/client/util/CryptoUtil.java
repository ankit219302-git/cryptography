package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.cybsec.cryptography.client.CryptoConstants.DEFAULT_AES_KEY_SIZE_BITS;
import static com.cybsec.cryptography.client.CryptoConstants.DEFAULT_SYMMETRIC_CRYPTOGRAPHY;
import static com.cybsec.cryptography.encryption.EncryptionConstants.SECURE_RANDOM;

public class CryptoUtil {
    /**
     * Generate a new 256-bit AES SecretKey.
     * @return 256-bit AES key
     */
    public static SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(DEFAULT_SYMMETRIC_CRYPTOGRAPHY);
        kg.init(DEFAULT_AES_KEY_SIZE_BITS, SECURE_RANDOM);
        return kg.generateKey();
    }

    /**
     * Fetch AES key from the specified key file.
     * @param aesKeyFilePath AES key file path
     * @return AES Key
     */
    public static SecretKey getAesKey(String aesKeyFilePath) throws IOException {
        if (StringUtils.isBlank(aesKeyFilePath)) {
            throw new IllegalArgumentException("Invalid AES key path");
        }
        byte[] keyBytes = Files.readAllBytes(Path.of(aesKeyFilePath));
        return new SecretKeySpec(keyBytes, DEFAULT_SYMMETRIC_CRYPTOGRAPHY);
    }

    /**
     * Base64 encode byte data to string.
     * @param data Data to be encoded
     * @return Base64 encoded string
     */
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Base64 decode encoded data to byte array.
     * @param data Base64 encoded data to be decoded
     * @return Base64 decoded byte array
     */
    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
