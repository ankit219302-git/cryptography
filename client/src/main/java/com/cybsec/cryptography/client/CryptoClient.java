package com.cybsec.cryptography.client;

import com.cybsec.cryptography.client.factory.CryptoFactory;
import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.encryption.Encryption;

public class CryptoClient {
    private Encryption encryption = null;
    private Decryption decryption = null;

    private CryptoClient() {}

    public CryptoClient(CryptoFactory cryptoFactory) {
        this.encryption = cryptoFactory.getEncryption();
        this.decryption = cryptoFactory.getDecryption();
    }

    public Encryption getEncryption() {
        return this.encryption;
    }

    public Decryption getDecryption() {
        return this.decryption;
    }
}
