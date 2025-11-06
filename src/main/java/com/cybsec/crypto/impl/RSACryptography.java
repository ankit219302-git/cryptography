package com.cybsec.crypto.impl;

import com.cybsec.crypto.Cryptography;
import org.apache.commons.codec.DecoderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import static com.cybsec.crypto.encryption.util.EncryptionUtil.*;

public class RSACryptography implements Cryptography {
    @Override
    public void performCryptography(String action) throws IOException, DecoderException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        Map<String, String> keyPairMap = new HashMap<>();
        Scanner scannerInput = new Scanner(System.in);
        String outputFilePath = null;
        System.out.print("Enter the Request/Response file path: ");
        String jsonFilePath = scannerInput.nextLine();
        String plainText = new String(Files.readAllBytes(Paths.get(jsonFilePath)));
        System.out.print("Enter the process to follow (E(encryption) / D(decryption)): ");
        String processToFollow = scannerInput.nextLine();
        if (processToFollow.equalsIgnoreCase("E")) {
            System.out.print("Enter the public key file path: ");
            String publicKeyJson = scannerInput.nextLine();
            String publickKey = new String(Files.readAllBytes(Paths.get(publicKeyJson)));
            getEncryptedKeyPairMap(publickKey,keyPairMap, plainText);
            System.out.print("Enter the output path: ");
            String outputPath = scannerInput.nextLine();
            outputFilePath = outputPath;
        } else if (processToFollow.equalsIgnoreCase("D")) {
            System.out.print("Enter the api-key : ");
            String apiId = scannerInput.nextLine();
            System.out.print("Enter the private key file path: ");
            String privateKeyJson = scannerInput.nextLine();
            String privateKey = new String(Files.readAllBytes(Paths.get(privateKeyJson)));
            getDecryptedKeyPairMap(privateKey, keyPairMap, plainText, apiId);
            System.out.print("Enter the output path: ");
            String outputPath = scannerInput.nextLine();
            outputFilePath = outputPath;
        }
        generateOutputFile(keyPairMap, outputFilePath);
        scannerInput.close();
    }
}
