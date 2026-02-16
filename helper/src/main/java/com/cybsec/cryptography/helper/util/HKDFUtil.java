package com.cybsec.cryptography.helper.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

//HMAC-based Key Derivation Function
public final class HKDFUtil {
    private static final String MAC_ALGO = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private HKDFUtil() {}

    private static byte[] extract(byte[] salt, byte[] inputKeyingMaterial)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(MAC_ALGO);
        mac.init(new SecretKeySpec(
                salt != null ? salt : new byte[HASH_LEN],
                MAC_ALGO
        ));
        return mac.doFinal(inputKeyingMaterial);
    }

    private static byte[] expand(byte[] pseudoRandomKey, byte[] info, int length)
            throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance(MAC_ALGO);
        mac.init(new SecretKeySpec(pseudoRandomKey, MAC_ALGO));

        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        int counter = 1;

        while (offset < length) {
            mac.reset();
            mac.update(t);
            if (info != null) {
                mac.update(info);
            }
            mac.update((byte) counter++);

            t = mac.doFinal();
            int copyLen = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, copyLen);
            offset += copyLen;
        }

        return result;
    }

    /**
     * HMAC-based key derivation function to get a secret key from provided input.
     * @param inputKeyingMaterial Secret input key material for generating output key
     * @param salt A non-secret, typically random input used during the extract phase to increase robustness and protect against weak IKM
     * @param info An optional but crucial field used in the expand phase to bind derived keys to specific application-context, ensuring key separation and security
     * @param length Specifies the exact number of bytes of output keying material to generate during the expansion step
     * @return Secret key
     */
    public static byte[] deriveKey(
            byte[] inputKeyingMaterial,
            byte[] salt,
            byte[] info,
            int length
    ) throws NoSuchAlgorithmException, InvalidKeyException {

        byte[] pseudoRandomKey = extract(salt, inputKeyingMaterial);
        byte[] outputKeyingMaterial = expand(pseudoRandomKey, info, length);

        Arrays.fill(pseudoRandomKey, (byte) 0);
        return outputKeyingMaterial;
    }
}

