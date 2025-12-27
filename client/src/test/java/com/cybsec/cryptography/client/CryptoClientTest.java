package com.cybsec.cryptography.client;

import com.cybsec.cryptography.client.factory.AsymmetricCryptoFactory;
import com.cybsec.cryptography.client.factory.SymmetricCryptoFactory;
import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.encryption.Encryption;
import com.cybsec.cryptography.helper.transformation.asymmetric.impl.RSATransformation;
import com.cybsec.cryptography.helper.transformation.symmetric.impl.AESTransformation;
import com.cybsec.cryptography.helper.util.CryptoUtil;
import com.cybsec.cryptography.helper.util.KeyStoreUtil;
import com.cybsec.cryptography.helper.util.PasswordUtil;
import org.junit.jupiter.api.Test;

import java.security.Key;

public class CryptoClientTest {
    private static final String CRYPTO_KEYSTORE_PASS_VAR = "CRYPTO_KEYSTORE_PASS";
    private static final String CRYPTO_RSA_ALIAS_VAR = "CRYPTO_RSA_ALIAS";

    @Test
    public void testAESCryptography() {
        CryptoClient cryptoClient = new CryptoClient(new SymmetricCryptoFactory());
        Encryption encryption = cryptoClient.getEncryption();
        Decryption decryption = cryptoClient.getDecryption();
        byte[] plainText = "Hello World".getBytes();
        try {
            Key key = CryptoUtil.getAesKey("../client/src/test/resources/keys/aes/aes.key");
            byte[] cipherText = encryption.encrypt(plainText, key, AESTransformation.GCM);
            byte[] decryptedText = decryption.decrypt(cipherText, key, AESTransformation.GCM);
            assert PasswordUtil.constantTimeEquals(plainText, decryptedText);
        } catch (Exception e) {
            assert false;
        }
    }

    @Test
    public void testAESCryptographyWithBase64Coding() {
        CryptoClient cryptoClient = new CryptoClient(new SymmetricCryptoFactory());
        Encryption encryption = cryptoClient.getEncryption();
        Decryption decryption = cryptoClient.getDecryption();
        byte[] plainText = "Hello World".getBytes();
        try {
            Key key = CryptoUtil.getAesKey("../client/src/test/resources/keys/aes/aes.key");
            String cipherText = CryptoUtil.base64Encode(encryption.encrypt(plainText, key, AESTransformation.GCM));
            byte[] decryptedText = decryption.decrypt(CryptoUtil.base64Decode(cipherText), key, AESTransformation.GCM);
            assert PasswordUtil.constantTimeEquals(plainText, decryptedText);
        } catch (Exception e) {
            assert false;
        }
    }

    @Test
    public void testRSACryptography() {
        CryptoClient cryptoClient = new CryptoClient(new AsymmetricCryptoFactory());
        Encryption encryption = cryptoClient.getEncryption();
        Decryption decryption = cryptoClient.getDecryption();
        byte[] plainText = "Hello World".getBytes();
        String keyStorePath = "../client/src/test/resources/keystore/crypto-keystore.p12";
        try {
            char[] keyStorePassword = KeyStoreUtil.getKeyStorePassFromEnvVars(CRYPTO_KEYSTORE_PASS_VAR);
            String keyAlias = CryptoUtil.getDataFromEnvVars(CRYPTO_RSA_ALIAS_VAR);
            Key publicKey = KeyStoreUtil.getRSAPublicKeyFromPKCS12KeyStore(keyStorePath, keyStorePassword, keyAlias);
            keyStorePassword = KeyStoreUtil.getKeyStorePassFromEnvVars(CRYPTO_KEYSTORE_PASS_VAR);
            Key privateKey = KeyStoreUtil.getRSAPrivateKeyFromPKCS12KeyStore(keyStorePath, keyStorePassword, keyAlias);
            byte[] cipherText = encryption.encrypt(plainText, publicKey, RSATransformation.OAEP_SHA256_MGF1);
            byte[] decryptedText = decryption.decrypt(cipherText, privateKey, RSATransformation.OAEP_SHA256_MGF1);
            assert PasswordUtil.constantTimeEquals(plainText, decryptedText);
        } catch (Exception e) {
            assert false;
        }
    }
}
