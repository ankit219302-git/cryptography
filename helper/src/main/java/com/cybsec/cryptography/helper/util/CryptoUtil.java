package com.cybsec.cryptography.helper.util;

import com.cybsec.cryptography.helper.transformation.asymmetric.impl.ECCTransformation;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static com.cybsec.cryptography.helper.Constants.*;

public final class CryptoUtil {
    private CryptoUtil() {}

    /**
     * Generate asymmetric EC key pair.
     * @return EC key pair
     */
    public static KeyPair generateEcKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ECCTransformation.P256.getAlgorithm());
        kpg.initialize(ECCTransformation.P256.getParameterSpec());
        return kpg.generateKeyPair();
    }

    /**
     * Generate asymmetric RSA key pair with default key size (2048 bits).
     * @return RSA key pair
     */
    public static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        return generateRsaKeyPair(DEFAULT_RSA_KEY_SIZE_BITS);
    }

    /**
     * Generate asymmetric RSA key pair with specified key size.
     * @return RSA key pair
     */
    public static KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException {
        if (keySize < DEFAULT_RSA_KEY_SIZE_BITS) {
            throw new IllegalArgumentException("RSA key size must be >= " + DEFAULT_RSA_KEY_SIZE_BITS + " bits");
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(DEFAULT_ASYMMETRIC_CRYPTOGRAPHY);
        kpg.initialize(keySize, SECURE_RANDOM);
        return kpg.generateKeyPair();
    }

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
     * Generate a X509 self-signed certificate for a public-private key pair.
     * @param keyPair Public-private key pair for creating the certificate
     * @param subjectDn Subject Distinguished Name - a unique identifier composed of several attributes that describe the certificate's owner
     * @param signatureAlgorithm Signing algorithm to sign the certificate with
     * @return X509 self-signed certificate
     */
    public static X509Certificate generateSelfSignedCertificate(
            KeyPair keyPair,
            String subjectDn,
            String signatureAlgorithm
    ) throws OperatorCreationException, CertificateException {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(now);
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .build(keyPair.getPrivate());
        X509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        serial,
                        notBefore,
                        notAfter,
                        subject,
                        keyPair.getPublic()
                );
        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    /**
     * Validate certificate with private key.
     * @param certificate Certificate to validate with private key
     * @param privateKey Private key to validate with certificate
     * @return true if validation passes, else false
     */
    public static boolean isCertificateValidForPrivateKey(Certificate certificate, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey publicKey = certificate.getPublicKey();
        String signatureAlgorithm = switch (privateKey.getAlgorithm()) {
            case DEFAULT_ASYMMETRIC_CRYPTOGRAPHY -> RSA_SIGNING_ALGORITHM;
            case EC_ASYMMETRIC_CRYPTOGRAPHY -> EC_SIGNING_ALGORITHM;
            default -> throw new IllegalArgumentException("Unsupported key algorithm: " + privateKey.getAlgorithm());
        };
        byte[] testData = "key-validation-test".getBytes(StandardCharsets.UTF_8);

        // Sign using private key
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(privateKey);
        signer.update(testData);
        byte[] signature = signer.sign();

        // Verify using certificate public key
        Signature verifier = Signature.getInstance(signatureAlgorithm);
        verifier.initVerify(publicKey);
        verifier.update(testData);

        return verifier.verify(signature);
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
        SecretKey secretKey = new SecretKeySpec(keyBytes, DEFAULT_SYMMETRIC_CRYPTOGRAPHY);
        PasswordUtil.wipe(keyBytes);
        return secretKey;
    }

    /**
     * Fetches data from stored environment variable as String.
     * NOT TO BE USED for fetching sensitive data.
     * @param envVar Environment variable name
     * @return Data as String
     */
    public static String getDataFromEnvVars(String envVar) {
        if (StringUtils.isBlank(envVar)) {
            throw new IllegalArgumentException("Invalid environment variable");
        }
        return System.getenv(envVar);
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
     * @param data Data to be decoded
     * @return Base64 decoded byte array
     */
    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
