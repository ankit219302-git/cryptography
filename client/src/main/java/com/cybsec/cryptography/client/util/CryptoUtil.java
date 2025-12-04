package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class CryptoUtil {
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_PASS_VAR = "KEYSTORE_PASSWORD";

    private static KeyStore loadKeyStore(String keyStorePath, String keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(keyStorePath)) {
            throw new IllegalArgumentException("Invalid keystore path");
        }
        if (StringUtils.isBlank(keyStorePassword)) {
            throw new IllegalArgumentException("Invalid keystore password");
        }
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (var in = Files.newInputStream(Path.of(keyStorePath))) {
            ks.load(in, keyStorePassword.toCharArray());
        }
        return ks;
    }

    public static PrivateKey getPrivateKeyFromKeyStore(String keyStorePath, String keyStorePassword, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStorePath, keyStorePassword);
        if (!ks.containsAlias(alias)) {
            throw new IllegalArgumentException("Alias '" + alias + "' not found in keystore");
        }
        Key key = ks.getKey(alias, keyStorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        throw new IllegalArgumentException("Alias does not contain a private key");
    }

    public static PublicKey getPublicKeyFromKeyStore(String keyStorePath, String keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStorePath, keyStorePassword);
        Certificate cert = ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalArgumentException("Alias '" + alias + "' does not contain a certificate/public key");
        }
        return cert.getPublicKey();
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
