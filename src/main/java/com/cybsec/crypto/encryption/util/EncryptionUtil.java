package com.cybs.crypto.encryption.util;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;

public class EncryptionUtil {
    public static SecretKey generateAESSecretKey(int keyBitSize) throws NoSuchAlgorithmException {
        System.out.println("Inside generateAESSecretKey() in EncryptionUtil");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(keyBitSize, secureRandom);
        return keyGenerator.generateKey();
    }

    public static String bytesToHex(byte[] bytes) {
        System.out.println("bytes to hex start");
        final char[] hexaAe = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexaAe[v >>> 4];
            hexChars[j * 2 + 1] = hexaAe[v & 0x0F];
        }
        System.out.println("bytes to hex end");
        return new String(hexChars);
    }

    public static String encryptRequestUsingAES(String hexKey, String responseBody, byte[] raw)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecoderException {
        System.out.println("Inside encryptResponseUsingAES() in EncryptionUtil");
        System.out.println("HexKey" + hexKey);
        byte[] iv = Arrays.copyOfRange(raw, 0, 16);
        String encyptedResponse = "";
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        encyptedResponse = bytesToHex(cipher.doFinal(responseBody.getBytes(StandardCharsets.UTF_8)));
        System.out.println("Exiting encryptResponseUsingAES() in EncryptionUtil");
        System.out.println("Exiting encryptResponseUsingAES() in EncryptionUtil " + encyptedResponse);
        return encyptedResponse;
    }

    public static String encryptSecretKeyUsingRSA(String publicKey, String hexKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, DecoderException {
        System.out.println("Inside encryptSecretKeyUsingRSA() in EncryptionUtil1");
        String encryptedSecretKey = "";
        byte[] resPublic = Hex.decodeHex(publicKey.toCharArray());
        PublicKey publicKeySec = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(resPublic));
        System.out.println("before encrypting complete request");
        encryptedSecretKey = encryptOTK(publicKeySec, hexKey);
        System.out.println("after encrypting complete request");
        System.out.println("Exiting encryptSecretKeyUsingRSA() in EncryptionUtil " + encryptedSecretKey);
        return encryptedSecretKey;
    }

    private static String encryptOTK(PublicKey publicKey, String secretKeyString) {
        System.out.println("Inside encryptOTK() in EncryptionUtil");
        String encodeedString = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encodeedString = Base64
                    .encodeBase64String(cipher.doFinal(secretKeyString.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exp) {
            System.out.println("Exception in encryptOTK in EncryptionUtil " + exp);
        }
        System.out.println("Inside encryptOTK() in EncryptionUtil");
        return encodeedString;
    }

    public static String decryptSecretKeyUsingRSA(String privateKeySec, String encyptedSecretKey)
            throws DecoderException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        System.out.println("Entering decryptSecretKeyUsingRSA() in EncriptionFilter");
        String decryptedApiRequest = "";
        byte[] resPrivate = Hex.decodeHex(privateKeySec.toCharArray());
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(resPrivate));
        System.out.println("before decryption complete request");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedApiRequest = new String(cipher.doFinal(Base64.decodeBase64(encyptedSecretKey)),
                StandardCharsets.UTF_8);
        System.out.println("after decryption complete request");
        System.out.println("Exiting decryptSecretKeyUsingRSA() in EncriptionFilter");
        return decryptedApiRequest;
    }

    public static String decryptAESRequest(String encryptedAESRequest, String secretKeyString)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        System.out.println("Inside decryptAESRequest() in EncryptionFilter2");
        String decrytRequest = "";
        byte[] keyBytes = hexStringToByteArray(secretKeyString);
        byte[] iv = Arrays.copyOfRange(keyBytes, 0, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));
        byte[] recoveredPlaintextBytes = cipher.doFinal(hexStringToByteArray(encryptedAESRequest));
        decrytRequest = new String(recoveredPlaintextBytes);
        System.out.println("Exiting decryptAESRequest() in EncryptionFilter");
        return decrytRequest;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void generateOutputFile(Map<String, String> keyPairMap, String outputFilePath) throws IOException {
        File file = new File(outputFilePath);
        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file))) {
            for (Entry<String, String> entry : keyPairMap.entrySet()) {
                bufferedWriter.write(entry.getKey() + ":" + entry.getValue());
                bufferedWriter.newLine();
            }
            bufferedWriter.flush();
        }
    }

    public static void getEncryptedKeyPairMap(String publicKey, Map<String, String> keyPairMap,
                                               String plainText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, DecoderException {
        System.out.println("------------- AES Encryption Started");
        String encryptedBody;
        String encryptedKey;
        SecretKey secretKey = generateAESSecretKey(128);
        byte[] bytes = secretKey.getEncoded();
        String hexKey = bytesToHex(bytes);
        keyPairMap.put("EncryptedAESKey", hexKey);
        System.out.println("Inside generateAESSecretKey() in EncryptionUtil " + hexKey);
        encryptedBody = encryptRequestUsingAES(hexKey, plainText, bytes);
        keyPairMap.put("EncryptedRequestBody", encryptedBody);
        encryptedKey = encryptSecretKeyUsingRSA(publicKey,hexKey);
        keyPairMap.put("api-key", encryptedKey);
        System.out.println("-------------AES Encryption Completed : " + encryptedBody);
    }

    public static void getDecryptedKeyPairMap(String privateKey, Map<String, String> keyPairMap,
                                               String plainText, String apiId)
            throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        System.out.println("-------------RSA Decryption Started");
        String secretKeyString = decryptSecretKeyUsingRSA(privateKey, apiId);
        keyPairMap.put("secretKeyString", secretKeyString);
        System.out.println("-------------RSA Decryption Completed");
        System.out.println("-------------AES Decryption Started");
        System.out.println("decrypted Key" + secretKeyString);
        String decryptedResponseBody = decryptAESRequest(plainText, secretKeyString);
        keyPairMap.put("decryptedResponseBody", decryptedResponseBody);
        System.out.println("-------------AES Decryption Completed : " + decryptedResponseBody);
    }
}