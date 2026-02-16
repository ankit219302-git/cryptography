package com.cybsec.cryptography.decryption.hybrid;

import com.cybsec.cryptography.decryption.Decryption;
import com.cybsec.cryptography.helper.transformation.Transformation;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface HybridDecryption extends Decryption {
    @Override
    byte[] decrypt(byte[] data, Key key, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException;
}
