package com.cybsec.cryptography.client.factory;

import com.cybsec.cryptography.decryption.asymmetric.AsymmetricDecryption;
import com.cybsec.cryptography.decryption.asymmetric.impl.RSADecryption;
import com.cybsec.cryptography.encryption.asymmetric.AsymmetricEncryption;
import com.cybsec.cryptography.encryption.asymmetric.impl.RSAEncryption;

import static com.cybsec.cryptography.client.CryptoConstants.DEFAULT_ASYMMETRIC_CRYPTOGRAPHY;

public class AsymmetricCryptoFactory implements CryptoFactory {
    private final String asymmetricCryptoType;

    public AsymmetricCryptoFactory() {
        this.asymmetricCryptoType = DEFAULT_ASYMMETRIC_CRYPTOGRAPHY;
    }

    public AsymmetricCryptoFactory(String type) {
        this.asymmetricCryptoType = type;
    }

    /**
     * Get encryption object based on asymmetric cryptography type.
     * @return Encryption object
     */
    @Override
    public AsymmetricEncryption getEncryption() {
        if (DEFAULT_ASYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(this.asymmetricCryptoType)) {
            return new RSAEncryption();
        }
        throw new IllegalArgumentException("No implementation available for cryptography type '" + this.asymmetricCryptoType + "'");
    }

    /**
     * Get decryption object based on asymmetric cryptography type.
     * @return Decryption object
     */
    @Override
    public AsymmetricDecryption getDecryption() {
        if (DEFAULT_ASYMMETRIC_CRYPTOGRAPHY.equalsIgnoreCase(this.asymmetricCryptoType)) {
            return new RSADecryption();
        }
        throw new IllegalArgumentException("No implementation available for cryptography type '" + this.asymmetricCryptoType + "'");
    }
}
