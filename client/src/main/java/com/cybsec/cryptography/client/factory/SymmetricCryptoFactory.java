package com.cybsec.cryptography.client.factory;

import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.decryption.impl.AESDecryption;
import com.cybsec.cryptography.encryption.Encryption;
import com.cybsec.cryptography.encryption.impl.AESEncryption;

import static com.cybsec.cryptography.client.util.CryptoUtil.DEFAULT_SYMMETRIC_CRYPTOGRAPHY;

public class SymmetricCryptoFactory implements CryptoFactory {
    private final String symmetricCryptoType;

    public SymmetricCryptoFactory() {
        this.symmetricCryptoType =  DEFAULT_SYMMETRIC_CRYPTOGRAPHY;
    }

    public SymmetricCryptoFactory(String type) {
        this.symmetricCryptoType = type;
    }

    /**
     * Function to return encryption object based on symmetric cryptography type.
     * @return Encryption object
     */
    @Override
    public Encryption getEncryption() {
        if (DEFAULT_SYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(this.symmetricCryptoType)) {
            return new AESEncryption();
        }
        throw new IllegalArgumentException("No implementation available for cryptography type '" + this.symmetricCryptoType + "'");
    }

    /**
     * Function to return decryption object based on symmetric cryptography type.
     * @return Decryption object
     */
    @Override
    public Decryption getDecryption() {
        if (DEFAULT_SYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(this.symmetricCryptoType)) {
            return new AESDecryption();
        }
        throw new IllegalArgumentException("No implementation available for cryptography type '" + this.symmetricCryptoType + "'");
    }
}
