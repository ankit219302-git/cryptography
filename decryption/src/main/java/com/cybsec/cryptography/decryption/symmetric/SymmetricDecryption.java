package com.cybsec.cryptography.decryption.symmetric;

import com.cybsec.cryptography.decryption.Decryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface SymmetricDecryption extends Decryption {
    @Override
    byte[] decrypt(byte[] data, Key key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    @Override
    byte[] decrypt(byte[] data, Key key, byte[] additionalAuthenticatedData)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;
}
