package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static com.cybsec.cryptography.client.CryptoConstants.DEFAULT_SYMMETRIC_CRYPTOGRAPHY;

public class KeyStoreUtil {
    private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";
    private static final String DEFAULT_KEYSTORE_PASS_VAR = "KEYSTORE_PASSWORD";

    /**
     * Create a new empty PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @return New keystore data
     */
    public static KeyStore createKeyStore(String keyStoreFilePath, String keyStorePassword) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        if (keyStoreFilePath == null) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        KeyStore ks = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
        Path ksPath = Path.of(keyStoreFilePath);
        if (Files.exists(ksPath)) {
            throw new IllegalArgumentException("Keystore already exists at: " + keyStoreFilePath);
        } else {
            ks.load(null, null); // Create empty PKCS12
        }
        saveKeyStore(keyStoreFilePath, keyStorePassword, ks);
        return ks;
    }

    /**
     * Load existing PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @return Existing keystore data
     */
    public static KeyStore loadKeyStore(String keyStoreFilePath, String keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(keyStoreFilePath)) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        KeyStore ks = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE);
        Path ksPath = Path.of(keyStoreFilePath);
        if (Files.exists(ksPath)) {
            try (InputStream in = Files.newInputStream(ksPath)) {
                ks.load(in, keyStorePassword.toCharArray());
            }
        } else {
            throw new IllegalArgumentException("Keystore doesn't exist");
        }
        return ks;
    }

    /**
     * Save a new/existing keystore to file.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param ks New/existing keystore
     */
    public static void saveKeyStore(String keyStoreFilePath, String keyStorePassword, KeyStore ks) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        try (FileOutputStream out = new FileOutputStream(keyStoreFilePath)) {
            ks.store(out, keyStorePassword.toCharArray());
        }
    }

    /**
     * Set a new secret key in existing keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param key Secret key to set in keystore
     * @param alias Key alias to set for the new key
     */
    public static void setSecretKeyEntryInKeyStore(String keyStoreFilePath, String keyStorePassword, SecretKey key, String alias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword);
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
        ks.setEntry(alias, entry, param);
        saveKeyStore(keyStoreFilePath, keyStorePassword, ks);
    }

    /**
     * Get keystore password stored in system environment variables.
     * @param keyStorePassVariable {Optional} Keystore password variable name to look for in system environment variables.
     * @return Keystore password
     */
    public static String getKeyStorePassFromEnvVars(String keyStorePassVariable) {
        keyStorePassVariable = StringUtils.isBlank(keyStorePassVariable) ? DEFAULT_KEYSTORE_PASS_VAR : keyStorePassVariable;
        String ksPassword = System.getenv(keyStorePassVariable);
        if (StringUtils.isBlank(ksPassword)) {
            throw new IllegalArgumentException("Environment variable '" + keyStorePassVariable + "' not set");
        }
        return ksPassword;
    }

    /**
     * Fetch private key from the specified PKCS12 keystore.
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
        if (!(key instanceof PrivateKey privateKey)) {
            throw new IllegalArgumentException("Alias does not contain a private key");
        }
        return privateKey;
    }

    /**
     * Fetch public key from the specified PKCS12 keystore.
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
     * Fetch Secret key from the specified PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return Secret Key
     */
    public static SecretKey getSecretKey(String keyStoreFilePath, String keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
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
        return secretKey;
    }

    /**
     * Fetch AES key from the specified PKCS12 keystore.
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
        if (!DEFAULT_SYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(secretKey.getAlgorithm())) {
            throw new IllegalArgumentException("Alias '" + alias + "' does not contain an AES key");
        }
        return secretKey;
    }
}
