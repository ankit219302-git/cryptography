package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static com.cybsec.cryptography.client.util.KeyStoreUtil.loadKeyStore;

public class CryptoUtil {
    private static final String AES = "AES";

    /**
     * Function to fetch private key from the specified PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return Private Key
     */
    public static PrivateKey getPrivateKey(String keyStoreFilePath, String keyStorePassword, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword);
        if (!ks.containsAlias(alias)) {
            throw new IllegalArgumentException("Alias '" + alias + "' not found in keystore");
        }
        Key key = ks.getKey(alias, keyStorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        throw new IllegalArgumentException("Alias does not contain a private key");
    }

    /**
     * Function to fetch public key from the specified PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return Public Key
     */
    public static PublicKey getPublicKey(String keyStoreFilePath, String keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("Alias '" + alias + "' does not contain a certificate/public key");
        }
        return cert.getPublicKey();
    }

    /**
     * Function to fetch AES key from the specified PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return AES Key
     */
    public static SecretKey getAesKey(String keyStoreFilePath, String keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword);
        Key key = ks.getKey(alias, keyStorePassword.toCharArray());
        if (key == null) {
            throw new IllegalArgumentException("No key found for alias: " + alias);
        }
        if (!(key instanceof SecretKey secretKey)) {
            throw new IllegalArgumentException("Alias does not contain a secret key");
        }
        if (!AES.equalsIgnoreCase(secretKey.getAlgorithm())) {
            throw new IllegalArgumentException("Alias '" + alias + "' does not contain an AES key");
        }

        return secretKey;
    }

    /**
     * Function to fetch AES key from the specified key file.
     * @param aesKeyFilePath AES key file path
     * @return AES Key
     */
    public static SecretKey getAesKey(String aesKeyFilePath) throws IOException {
        if (StringUtils.isBlank(aesKeyFilePath)) {
            throw new IllegalArgumentException("Invalid AES key path");
        }
        byte[] keyBytes = Files.readAllBytes(Path.of(aesKeyFilePath));
        return new SecretKeySpec(keyBytes, AES);
    }
}
