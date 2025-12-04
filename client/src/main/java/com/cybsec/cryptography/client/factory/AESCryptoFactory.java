package com.cybsec.cryptography.client.factory;

import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.decryption.impl.AESDecryption;
import com.cybsec.cryptography.encryption.Encryption;
import com.cybsec.cryptography.encryption.impl.AESEncryption;

class AESCryptoFactory implements CryptoFactory {
    @Override
    public Encryption getEncryption() {
        return new AESEncryption();
    }

    @Override
    public Decryption getDecryption() {
        return new AESDecryption();
    }
}
