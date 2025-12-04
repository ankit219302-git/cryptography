package com.cybsec.cryptography.encryption.impl;

import com.cybsec.cryptography.encryption.Encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

//import static com.cybsec.cryptography.encryption.util.EncryptionUtil.AES;
//
//public class AESEncryption implements Encryption {
//    @Override
//    public String encrypt(String data, String keyStorePath, String keyStoreAlias, String keyStorePassVariable) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        SecretKeySpec keySpec = new SecretKeySpec(keyStorePath.getBytes(), AES);
//        Cipher cipher = Cipher.getInstance(AES);
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
//        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
//        return Base64.getEncoder().encodeToString(encryptedBytes);
//    }
//}
