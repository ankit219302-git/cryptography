package com.cybsec.cryptography.client.factory;

import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.decryption.impl.RSADecryption;
import com.cybsec.cryptography.encryption.Encryption;
import com.cybsec.cryptography.encryption.impl.RSAEncryption;

class RSACryptoFactory implements CryptoFactory {
    @Override
    public Encryption getEncryption() {
        return new RSAEncryption();
    }

    @Override
    public Decryption getDecryption() {
        return new RSADecryption();
    }
}
