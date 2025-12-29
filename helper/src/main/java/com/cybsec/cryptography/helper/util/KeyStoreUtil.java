package com.cybsec.cryptography.helper.util;

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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.cybsec.cryptography.helper.Constants.DEFAULT_SYMMETRIC_CRYPTOGRAPHY;

public final class KeyStoreUtil {
    private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";
    private static final String DEFAULT_KEYSTORE_PASS_VAR = "KEYSTORE_PASSWORD";

    private KeyStoreUtil() {}

    /**
     * Create a new empty PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @return New PKCS12 keystore
     */
    public static KeyStore createPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        return createKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE);
    }

    /**
     * Create a new empty keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @return New keystore
     */
    public static KeyStore createKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        if (keyStoreFilePath == null) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (PasswordUtil.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        if (StringUtils.isBlank(keyStoreType)) {
            keyStoreType = DEFAULT_KEYSTORE_TYPE;
        }
        KeyStore ks = KeyStore.getInstance(keyStoreType);
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
     * @return Existing PKCS12 keystore
     */
    public static KeyStore loadPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        return loadKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE);
    }

    /**
     * Load existing keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @return Existing keystore
     */
    public static KeyStore loadKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(keyStoreFilePath)) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (PasswordUtil.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        if (StringUtils.isBlank(keyStoreType)) {
            keyStoreType = DEFAULT_KEYSTORE_TYPE;
        }
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        Path ksPath = Path.of(keyStoreFilePath);
        if (Files.exists(ksPath)) {
            try (InputStream in = Files.newInputStream(ksPath)) {
                ks.load(in, keyStorePassword);
            }
        } else {
            throw new IllegalArgumentException("Keystore doesn't exist");
        }
        PasswordUtil.wipe(keyStorePassword);
        return ks;
    }

    /**
     * Save a new/existing keystore to file.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param ks New/existing keystore
     */
    public static void saveKeyStore(String keyStoreFilePath, char[] keyStorePassword, KeyStore ks) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        try (FileOutputStream out = new FileOutputStream(keyStoreFilePath)) {
            ks.store(out, keyStorePassword);
        }
        PasswordUtil.wipe(keyStorePassword);
    }

    /**
     * Set a new secret key in existing PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param key Secret key to set in keystore
     * @param alias Key alias to set for the new key
     */
    public static void setSecretKeyEntryInPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword, SecretKey key, String alias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        setSecretKeyEntryInKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, key, alias);
    }

    /**
     * Set a new secret key in existing keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param key Secret key to set in keystore
     * @param alias Key alias to set for the new key
     */
    public static void setSecretKeyEntryInKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType, SecretKey key, String alias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(keyStorePassword);
        char[] ksPass = PasswordUtil.clone(keyStorePassword);
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        ks.setEntry(alias, entry, param);
        saveKeyStore(keyStoreFilePath, ksPass, ks);
        PasswordUtil.wipe(ksPass);
    }

    /**
     * Get keystore password stored in system environment variables.
     * @param keyStorePassVariable {Optional} Keystore password variable name to look for in system environment variables.
     * @return Keystore password
     */
    public static char[] getKeyStorePassFromEnvVars(String keyStorePassVariable) {
        if (StringUtils.isBlank(keyStorePassVariable)) {
            keyStorePassVariable = DEFAULT_KEYSTORE_PASS_VAR;
        }
        char[] ksPassword = PasswordUtil.getFromEnv(keyStorePassVariable);
        if (PasswordUtil.isBlank(ksPassword)) {
            throw new IllegalArgumentException("Environment variable '" + keyStorePassVariable + "' not set");
        }
        keyStorePassVariable = null;
        return ksPassword;
    }

    /**
     * Fetch RSA private key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return RSA Private Key
     */
    public static RSAPrivateKey getRSAPrivateKeyFromPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        return getRSAPrivateKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, alias);
    }

    /**
     * Fetch RSA private key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param alias Key alias
     * @return RSA Private Key
     */
    public static RSAPrivateKey getRSAPrivateKeyFromKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        char[] ksPass = PasswordUtil.clone(keyStorePassword);
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        if (!ks.containsAlias(alias)) {
            throw new IllegalArgumentException("Alias '" + alias + "' not found in keystore");
        }
        Key key = ks.getKey(alias, ksPass);
        if (key == null) {
            throw new IllegalArgumentException("Keystore does not contain RSA private key with alias '" + alias + "'");
        }
        if (!(key instanceof RSAPrivateKey privateKey)) {
            throw new IllegalArgumentException("Alias does not contain RSA private key");
        }
        PasswordUtil.wipe(ksPass);
        return privateKey;
    }

    /**
     * Fetch RSA public key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return RSA Public Key
     */
    public static RSAPublicKey getRSAPublicKeyFromPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        return getRSAPublicKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, alias);
    }

    /**
     * Fetch RSA public key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param alias Key alias
     * @return RSA Public Key
     */
    public static RSAPublicKey getRSAPublicKeyFromKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("Keystore does not contain RSA public key with alias '" + alias + "'");
        }
        if (!(cert.getPublicKey() instanceof RSAPublicKey publicKey)) {
            throw new IllegalArgumentException("Alias does not contain RSA public key");
        }
        return publicKey;
    }

    /**
     * Fetch certificate from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return Certificate
     */
    public static Certificate getCertificateFromPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        return getCertificateFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, alias);
    }

    /**
     * Fetch certificate from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param alias Key alias
     * @return Certificate
     */
    public static Certificate getCertificateFromKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("Keystore does not contain a certificate with alias '" + alias + "'");
        }
        return cert;
    }

    /**
     * Fetch Secret key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return Secret Key
     */
    public static SecretKey getSecretKeyFromPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getSecretKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, alias);
    }

    /**
     * Fetch Secret key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param alias Key alias
     * @return Secret Key
     */
    public static SecretKey getSecretKeyFromKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        char[] ksPass = PasswordUtil.clone(keyStorePassword);
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        Key key = ks.getKey(alias, ksPass);
        if (key == null) {
            throw new IllegalArgumentException("Keystore does not contain a secret key with alias '" + alias + "'");
        }
        if (!(key instanceof SecretKey secretKey)) {
            throw new IllegalArgumentException("Alias does not contain a secret key");
        }
        PasswordUtil.wipe(ksPass);
        return secretKey;
    }

    /**
     * Fetch AES key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return AES Key
     */
    public static SecretKey getAesKeyFromPKCS12KeyStore(String keyStoreFilePath, char[] keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getAesKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, alias);
    }

    /**
     * Fetch AES key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param alias Key alias
     * @return AES Key
     */
    public static SecretKey getAesKeyFromKeyStore(String keyStoreFilePath, char[] keyStorePassword, String keyStoreType, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        SecretKey secretKey = getSecretKeyFromKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType, alias);
        if (!DEFAULT_SYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(secretKey.getAlgorithm())) {
            throw new IllegalArgumentException("Alias '" + alias + "' does not contain an AES key");
        }
        return secretKey;
    }
}
