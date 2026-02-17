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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.cybsec.cryptography.helper.Constants.*;
import static com.cybsec.cryptography.helper.util.CryptoUtil.isCertificateValidForPrivateKey;

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
    public static KeyStore createPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword
    ) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        return createKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE);
    }

    /**
     * Create a new empty keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @return New keystore
     */
    public static KeyStore createKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType
    ) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
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
    public static KeyStore loadPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword
    ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        return loadKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE);
    }

    /**
     * Load existing keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @return Existing keystore
     */
    public static KeyStore loadKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType
    ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
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
    public static void saveKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            KeyStore ks
    ) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
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
     * @param keyPassword Key entry protection password
     * @param alias Key alias to set for the new key
     */
    public static void setSecretKeyEntryInPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            SecretKey key,
            char[] keyPassword,
            String alias
    ) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        setSecretKeyEntryInKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, key, keyPassword, alias);
    }

    /**
     * Set a new secret key in existing keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param key Secret key to set in keystore
     * @param keyPassword Key entry protection password
     * @param alias Key alias to set for the new key
     */
    public static void setSecretKeyEntryInKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            SecretKey key,
            char[] keyPassword,
            String alias
    ) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter keyPass = new KeyStore.PasswordProtection(keyPassword);
        char[] ksPass = PasswordUtil.clone(keyStorePassword);
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        ks.setEntry(alias, keyEntry, keyPass);
        saveKeyStore(keyStoreFilePath, ksPass, ks);
        PasswordUtil.wipe(ksPass);
        PasswordUtil.wipe(keyPassword);
    }

    /**
     * Set a new key pair entry in existing PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyPair Key pair to set in keystore
     * @param keyPassword Key pair entry protection password
     * @param certificate Self-signed certificate containing public key
     * @param alias Alias to set for the new key pair
     */
    public static void setKeyPairEntryInPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            KeyPair keyPair,
            char[] keyPassword,
            Certificate certificate,
            String alias
    ) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        setKeyPairEntryInKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, keyPair, keyPassword, certificate, alias);
    }

    /**
     * Set a new key pair entry in existing keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param keyPair Key pair to set in keystore
     * @param keyPassword Key pair entry protection password
     * @param certificate Self-signed certificate containing public key
     * @param alias Alias to set for the new key pair
     */
    public static void setKeyPairEntryInKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            KeyPair keyPair,
            char[] keyPassword,
            Certificate certificate,
            String alias
    ) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        if (!isCertificateValidForPrivateKey(certificate, keyPair.getPrivate())) {
            throw new IllegalArgumentException("Incompatible certificate and private key");
        }
        char[] ksPass = PasswordUtil.clone(keyStorePassword);
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        ks.setKeyEntry(
                alias,
                keyPair.getPrivate(),
                keyPassword,
                new Certificate[]{certificate}
        );
        saveKeyStore(keyStoreFilePath, ksPass, ks);
        PasswordUtil.wipe(ksPass);
        PasswordUtil.wipe(keyPassword);
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
     * Fetch asymmetric private key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyAlgorithm Key algorithm (Eg. RSA, EC)
     * @param keyPassword Key entry password
     * @param alias Key alias
     * @return Private Key
     */
    public static PrivateKey getPrivateKeyFromPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyAlgorithm,
            char[] keyPassword,
            String alias
    ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        return getPrivateKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, keyAlgorithm, keyPassword, alias);
    }

    /**
     * Fetch asymmetric private key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param keyAlgorithm Key algorithm (Eg. RSA, EC)
     * @param keyPassword Key entry password
     * @param alias Key alias
     * @return Private Key
     */
    public static PrivateKey getPrivateKeyFromKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            String keyAlgorithm,
            char[] keyPassword,
            String alias
    ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        if (!ks.containsAlias(alias)) {
            throw new IllegalArgumentException("Alias '" + alias + "' not found in keystore");
        }
        Key key = ks.getKey(alias, keyPassword);
        PasswordUtil.wipe(keyPassword);
        if (key == null) {
            throw new IllegalArgumentException("Keystore does not contain private key with alias '" + alias + "'");
        }
        return switch (keyAlgorithm) {
            case DEFAULT_ASYMMETRIC_CRYPTOGRAPHY -> {
                if (!(key instanceof RSAPrivateKey privateKey)) {
                    throw new IllegalArgumentException("Alias does not contain RSA private key");
                }
                yield privateKey;
            }
            case EC_ASYMMETRIC_CRYPTOGRAPHY -> {
                if (!(key instanceof ECPrivateKey privateKey)) {
                    throw new IllegalArgumentException("Alias does not contain EC private key");
                }
                yield privateKey;
            }
            default -> throw new IllegalArgumentException("Algorithm '" + keyAlgorithm + "' is not supported");
        };
    }

    /**
     * Fetch asymmetric public key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyAlgorithm Key algorithm (Eg. RSA, EC)
     * @param alias Key alias
     * @return Public Key
     */
    public static PublicKey getPublicKeyFromPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyAlgorithm,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        return getPublicKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, keyAlgorithm, alias);
    }

    /**
     * Fetch asymmetric public key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param keyAlgorithm Key algorithm (Eg. RSA, EC)
     * @param alias Key alias
     * @return Public Key
     */
    public static PublicKey getPublicKeyFromKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            String keyAlgorithm,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("Keystore does not contain public key with alias '" + alias + "'");
        }
        return switch (keyAlgorithm) {
            case DEFAULT_ASYMMETRIC_CRYPTOGRAPHY -> {
                if (!(cert.getPublicKey() instanceof RSAPublicKey publicKey)) {
                    throw new IllegalArgumentException("Alias does not contain RSA public key");
                }
                yield publicKey;
            }
            case EC_ASYMMETRIC_CRYPTOGRAPHY -> {
                if (!(cert.getPublicKey() instanceof ECPublicKey publicKey)) {
                    throw new IllegalArgumentException("Alias does not contain EC public key");
                }
                yield publicKey;
            }
            default -> throw new IllegalArgumentException("Algorithm '" + keyAlgorithm + "' is not supported");
        };
    }

    /**
     * Fetch certificate from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param alias Key alias
     * @return Certificate
     */
    public static Certificate getCertificateFromPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
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
    public static Certificate getCertificateFromKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
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
     * @param keyPassword Key entry password
     * @param alias Key alias
     * @return Secret Key
     */
    public static SecretKey getSecretKeyFromPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            char[] keyPassword,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getSecretKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, keyPassword, alias);
    }

    /**
     * Fetch Secret key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param keyPassword Key entry password
     * @param alias Key alias
     * @return Secret Key
     */
    public static SecretKey getSecretKeyFromKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            char[] keyPassword,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType);
        Key key = ks.getKey(alias, keyPassword);
        if (key == null) {
            throw new IllegalArgumentException("Keystore does not contain a secret key with alias '" + alias + "'");
        }
        if (!(key instanceof SecretKey secretKey)) {
            throw new IllegalArgumentException("Alias does not contain a secret key");
        }
        PasswordUtil.wipe(keyPassword);
        return secretKey;
    }

    /**
     * Fetch AES key from PKCS12 keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyPassword Key entry password
     * @param alias Key alias
     * @return AES Key
     */
    public static SecretKey getAesKeyFromPKCS12KeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            char[] keyPassword,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getAesKeyFromKeyStore(keyStoreFilePath, keyStorePassword, DEFAULT_KEYSTORE_TYPE, keyPassword, alias);
    }

    /**
     * Fetch AES key from the specified keystore.
     * @param keyStoreFilePath Keystore file path
     * @param keyStorePassword Keystore password
     * @param keyStoreType Keystore type (Default PKCS12, if null or empty)
     * @param keyPassword Key entry password
     * @param alias Key alias
     * @return AES Key
     */
    public static SecretKey getAesKeyFromKeyStore(
            String keyStoreFilePath,
            char[] keyStorePassword,
            String keyStoreType,
            char[] keyPassword,
            String alias
    ) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        SecretKey secretKey = getSecretKeyFromKeyStore(keyStoreFilePath, keyStorePassword, keyStoreType, keyPassword, alias);
        if (!DEFAULT_SYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(secretKey.getAlgorithm())) {
            throw new IllegalArgumentException("Alias '" + alias + "' does not contain an AES key");
        }
        return secretKey;
    }
}
