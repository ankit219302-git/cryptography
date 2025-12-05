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

    public static void createKeyStore(String keyStorePath, String keyStorePassword) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        if (keyStorePath == null) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        Path ksPath = Path.of(keyStorePath);
        if (Files.exists(ksPath)) {
            try (InputStream in = Files.newInputStream(ksPath)) {
                ks.load(in, keyStorePassword.toCharArray());
            }
        } else {
            ks.load(null, null); // Create empty PKCS12
        }
    }

    public static KeyStore loadKeyStore(String keyStorePath, String keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(keyStorePath)) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        Path ksPath = Path.of(keyStorePath);
        if (Files.exists(ksPath)) {
            try (InputStream in = Files.newInputStream(ksPath)) {
                ks.load(in, keyStorePassword.toCharArray());
            }
        } else {
            throw new IllegalArgumentException("Keystore doesn't exist");
        }
        return ks;
    }

    public static void updateKeyStore(String keyStorePath, String keyStorePassword, KeyStore ks) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        try (FileOutputStream out = new FileOutputStream(keyStorePath)) {
            ks.store(out, keyStorePassword.toCharArray());
        }
    }

    public static void insertSecretKeyInKeyStore(String keyStorePath, String keyStorePassword, SecretKey Key, String alias) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStorePath, keyStorePassword);
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(Key);
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
        ks.setEntry(alias, entry, param);
        updateKeyStore(keyStorePath, keyStorePassword, ks);
    }

    public static String getKeyStorePassFromEnvVars(String keyStorePassVariable) {
        keyStorePassVariable = StringUtils.isBlank(keyStorePassVariable) ? KEYSTORE_PASS_VAR : keyStorePassVariable;
        String ksPassword = System.getenv(keyStorePassVariable);
        if (StringUtils.isBlank(ksPassword)) {
            throw new IllegalArgumentException("Environment variable '" + keyStorePassVariable + "' is not set");
        }
        return ksPassword;
    }
}
