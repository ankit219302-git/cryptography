package com.cybsec.cryptography.encryption;

import com.cybsec.cryptography.helper.transformation.Transformation;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public interface Encryption {
    byte[] encrypt(byte[] data, Key key, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException;

    default byte[] encrypt(byte[] data, Key key, byte[] additionalAuthenticatedData, Transformation transformation)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        throw new UnsupportedOperationException("Additional Authenticated Data (AAD) not supported");
    }
}
