package com.cybsec.cryptography.client.factory;

import com.cybsec.cryptography.decryption.hybrid.HybridDecryption;
import com.cybsec.cryptography.decryption.hybrid.impl.ECIESDecryption;
import com.cybsec.cryptography.encryption.hybrid.HybridEncryption;
import com.cybsec.cryptography.encryption.hybrid.impl.ECIESEncryption;

import static com.cybsec.cryptography.helper.Constants.DEFAULT_HYBRID_CRYPTOGRAPHY;

public class HybridCryptoFactory implements CryptoFactory {
    private final String hybridCryptoType;

    public HybridCryptoFactory() {
        this.hybridCryptoType = DEFAULT_HYBRID_CRYPTOGRAPHY;
    }

    public HybridCryptoFactory(String type) {
        this.hybridCryptoType = type;
    }

    /**
     * Get encryption object based on hybrid cryptography type.
     * @return Encryption object
     */
    @Override
    public HybridEncryption getEncryption() {
        if (DEFAULT_HYBRID_CRYPTOGRAPHY.equalsIgnoreCase(this.hybridCryptoType)) {
            return new ECIESEncryption();
        }
        throw new IllegalArgumentException("No implementation available for cryptography type '" + this.hybridCryptoType + "'");
    }

    /**
     * Get decryption object based on hybrid cryptography type.
     * @return Decryption object
     */
    @Override
    public HybridDecryption getDecryption() {
        if (DEFAULT_HYBRID_CRYPTOGRAPHY.equalsIgnoreCase(this.hybridCryptoType)) {
            return new ECIESDecryption();
        }
        throw new IllegalArgumentException("No implementation available for cryptography type '" + this.hybridCryptoType + "'");
    }
}
