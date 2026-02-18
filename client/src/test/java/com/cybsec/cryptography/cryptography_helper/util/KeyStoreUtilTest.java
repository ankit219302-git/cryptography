package com.cybsec.cryptography.cryptography_helper.util;

import com.cybsec.cryptography.helper.util.CryptoUtil;
import com.cybsec.cryptography.helper.util.KeyStoreUtil;
import com.cybsec.cryptography.helper.util.PasswordUtil;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.Certificate;

import static com.cybsec.cryptography.client.CryptoClientTest.CRYPTO_EC_ALIAS_VAR;
import static com.cybsec.cryptography.client.CryptoClientTest.CRYPTO_EC_KEY_PASS_VAR;
import static com.cybsec.cryptography.helper.Constants.EC_SIGNING_ALGORITHM;

public class KeyStoreUtilTest {
    public static final String CRYPTO_KEYSTORE_PASS_VAR = "CRYPTO_KEYSTORE_PASS";

    @Disabled("To be run once to create keystore entry")
    @Test
    public void testSetKeyPairEntryInPKCS12KeyStore() {
        String keyStorePath = "../client/src/test/resources/keystore/crypto-keystore.p12";
        try {
            char[] keyStorePassword = KeyStoreUtil.getKeyStorePassFromEnvVars(CRYPTO_KEYSTORE_PASS_VAR);
            char[] ecKeyPassword = PasswordUtil.getFromEnv(CRYPTO_EC_KEY_PASS_VAR);
            String keyAlias = CryptoUtil.getDataFromEnvVars(CRYPTO_EC_ALIAS_VAR);
            KeyPair ecKeyPair = CryptoUtil.generateEcKeyPair();
            Certificate ecCertificate = CryptoUtil.generateSelfSignedCertificate(
                    ecKeyPair,
                    "CN=ec-cryptography-test",
                    EC_SIGNING_ALGORITHM
            );
            KeyStoreUtil.setKeyPairEntryInPKCS12KeyStore(
                    keyStorePath,
                    keyStorePassword,
                    ecKeyPair,
                    ecKeyPassword,
                    ecCertificate,
                    keyAlias
            );
            assert true;
        } catch (Exception e) {
            assert false;
        }
    }
}
