package com.cybsec.crypto;

import com.cybsec.crypto.factory.CryptoFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Crypto {
    Scanner scannerInput = new Scanner(System.in);

    public Cryptography getCryptography() {
        Map<String, String> keyPairMap = new HashMap<>();
        String outputFilePath = null;
        System.out.print("Enter type of encryption/decryption required (eg. RSA/AES): ");
        String method = scannerInput.nextLine();
        scannerInput.close();
        return new CryptoFactory().getCrypto(method.toLowerCase());
    }

    public String getCryptographyAction() {
        System.out.print("Encryption or Decryption , input either E or D: ");
        String action = scannerInput.nextLine();
        if (!action.equalsIgnoreCase("e") || !action.equalsIgnoreCase("d")) {
            System.err.println("----INVALID INPUT----");
            System.exit(1);
        }
        scannerInput.close();
        return action.toLowerCase();
    }
}