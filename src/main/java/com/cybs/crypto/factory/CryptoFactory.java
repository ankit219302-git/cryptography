package com.cybs.crypto.factory;

import com.cybs.crypto.Cryptography;
import com.cybs.crypto.impl.AESCryptography;
import com.cybs.crypto.impl.RSACryptography;

public class CryptoFactory {
    public Cryptography getCrypto(String type) {
        return switch (type) {
            case "rsa" -> new RSACryptography();
            case "aes" -> new AESCryptography();
            default -> throw new IllegalArgumentException("Invalid Crypto Algorithm");
        };
    }
}
