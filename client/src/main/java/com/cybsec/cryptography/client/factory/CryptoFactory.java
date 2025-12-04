package com.cybsec.cryptography.client.factory;

import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.encryption.Encryption;

public interface CryptoFactory {
    Encryption getEncryption();
    Decryption getDecryption();
}
