package com.cybsec.crypto.factory;

import com.cybsec.crypto.Cryptography;
import com.cybsec.crypto.impl.AESCryptography;
import com.cybsec.crypto.impl.RSACryptography;

public class CryptoFactory {
    public Cryptography getCrypto(String type) {
        return switch (type) {
            case "rsa" -> new RSACryptography();
            case "aes" -> new AESCryptography();
            default -> throw new IllegalArgumentException("Invalid Crypto Algorithm");
        };
    }
}
