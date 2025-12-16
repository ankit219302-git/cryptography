package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptoUtil {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final int DEFAULT_AES_KEY_SIZE_BITS = 256; // 256-bit key
    public static final String DEFAULT_SYMMETRIC_CRYPTOGRAPHY = "AES";
    public static final String DEFAULT_ASYMMETRIC_CRYPTOGRAPHY = "RSA";

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
}
