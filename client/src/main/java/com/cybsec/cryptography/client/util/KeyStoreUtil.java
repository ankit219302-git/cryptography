package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class KeyStoreUtil {
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_PASS_VAR = "KEYSTORE_PASSWORD";

    /**
     * Function to create a new empty PKCS12 keystore.
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
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
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
     * Function to load existing PKCS12 keystore.
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
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
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
     * Function to save a new/existing keystore to file.
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
     * Function to set a new secret key in existing keystore.
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
     * Function to get keystore password stored in system environment variables.
     * @param keyStorePassVariable {Optional} Keystore password variable name to look for in system environment variables.
     * @return Keystore password
     */
    public static String getKeyStorePassFromEnvVars(String keyStorePassVariable) {
        keyStorePassVariable = StringUtils.isBlank(keyStorePassVariable) ? KEYSTORE_PASS_VAR : keyStorePassVariable;
        String ksPassword = System.getenv(keyStorePassVariable);
        if (StringUtils.isBlank(ksPassword)) {
            throw new IllegalArgumentException("Environment variable '" + keyStorePassVariable + "' is not set");
        }
        return ksPassword;
    }
}
