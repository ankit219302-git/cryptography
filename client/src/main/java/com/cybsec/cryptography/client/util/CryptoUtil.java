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
    public static PrivateKey getPrivateKey(String keyStorePath, String keyStorePassword, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
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

    public static PublicKey getPublicKey(String keyStorePath, String keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
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

    public static SecretKey getAesKey(String keyStorePath, String keyStorePassword, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Invalid alias");
        }
        KeyStore ks = loadKeyStore(keyStorePath, keyStorePassword);
        Key key = ks.getKey(alias, keyStorePassword.toCharArray());
        if (key instanceof SecretKey) {
            return (SecretKey) key;
        }
        throw new IllegalArgumentException("Alias does not contain an AES key");
    }

    public static SecretKey getAesKey(String aesKeyPath) throws IOException {
        if (StringUtils.isBlank(aesKeyPath)) {
            throw new IllegalArgumentException("Invalid AES key path");
        }
        byte[] keyBytes = Files.readAllBytes(Path.of(aesKeyPath));
        return new SecretKeySpec(keyBytes, "AES");
    }
}
