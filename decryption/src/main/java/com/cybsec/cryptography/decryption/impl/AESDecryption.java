package com.cybsec.cryptography.decryption.impl;

import com.cybsec.cryptography.decryption.Decryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

//import static com.cybsec.cryptography.decryption.util.DecryptionUtil.AES;
//
//public class AESDecryption implements Decryption {
//    @Override
//    public String decrypt(String data, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), AES);
//        Cipher cipher = Cipher.getInstance(AES);
//        cipher.init(Cipher.DECRYPT_MODE, keySpec);
//        //byte[] decryptedBytes = cipher.doFinal(payload.getBytes());
//        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(data));
//        return new String(decryptedBytes);
//    }
//}
