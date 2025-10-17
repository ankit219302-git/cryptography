package com.cybs.crypto;

import org.apache.commons.codec.DecoderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class App {
    //private static final String AES_KEY = "073412646jfvjjyf0123456789abcdef"; // 32 bytes key for AES 256 Sample
    private static final String AES_KEY = "826d7247b7fcbeb283a0d9403aa58545";
    private static final String requestPayload = "YScLQ8cYOJFonuM1xFs0eLYEpmjx3F48oY2/jgPjSdL4H4WNmLGsLZhsr+vhz9WfUkinrJ+kseVuDkv++1pXt+PyJgVTSS1bFZNyMK+NM5lOMGyHJVveRc0ksZbZOu9yUaKa3oyZuyPbjXWlxsEv6A40zBfEJcahEngT+DezAfOeMI86ewlSpWwiUL7P3BdD0GAus5tAVGP0RSt8haFAYzVH9elX2+QPmaNCjGUyUxJfsWQi9IGwlZe173b4XTVR8eaQVyn/6b+j42DNcJ2bX+qmjS0twIowCjJ1s2yzmCb8LAlfIAxkZPCGmOg6UDCBPi38D3z5BDUQ5OIlH/Bzzdw42q53NVu0JBagn/rhyKBZslD+2kjrvqRoJjegEC7GUQG1JS5QPFwqGixCO1Ya9AOZwWE+WpXzCGZdtqLusWI=";
    private static final String responsePayload = "tpXoBS12hSjZE2SIrGNvdNoxVYgaUt3S0rqM5CHKHKc7HUkkroTqsiq7x6+FNhFXL6OlkMswIBN/6Up4lTL3FMlqYvjGa95LLhNMNF3IzioH+i+oLVTEmy/J34XV4JMyTLNR5lusVVXAqXbGnjyIoekkJPJPmRVMkNBpGd5t1fGnMqYRgOkn3efX8zpzgw+q9uQKndn/IlOifHQpAU0bccCbnI+feB43zV/UstJkhmx4mU5MJyC0mdPlNcNK7AALqzAdcKul5xk7Ow42E729QJyR4izgae0QZ9qbtg8P/pn8yjJxqleTnVmpJEYZI2UWVcG8bAaJGLisxhiYjde7BijscABWWkNUl90R6DO4U4C29ocVxf9H0DKdPl6/XZvQxGpgaSIbzPGPUwzRYvKlgDaWpFQXC4V5S/XpYdKJ5mAB9RUckKMmgdzTY2FWEHQcMDxVWbcGmxLaGKeXO7+Z/7XR+lHk7m/GIk3vmOVLqSJ5zWas0asRPOklV2cIE247S8KG5i1UKSOZzJdVGj7y5PlitAVcsO9biLl4WIqmxgcFP0Y4slExDoU5mgzK7e+UbkmBI/8K9mECgLwOIR01GiEqwY8+va4c1xjpNaOrKGmJb370ScX8Af3N1+PxNkOcKTqVCUkMgseDptPnIGQL2Ysu3+qSEOJR7Gnq5kU0T3axZQeyPXto9St7nNAWns1GXltVaxuiS4yswTrKdZoHpLKQPH3IeoOm+o8M6X/DW2DnsBom4caOgqcn+FYbhsrWPjVXX/i3PSveDjJcVcIFLv8aryeI89lf7/dmNf3AtsRCQc4xr6vfxUG7jDzewMBajY9YesQHNlZpBRqMzDlubwB1qO1SC4DlZYXyAdBJA1j3plL7qtES8kjXxg8/giLq1+KTCCfyQvPRTitTkuuRqehNxGLwMGuOtpTOzzI6K6k425y717fhp8R9LqtKxlytSgGVoe1etPOwLZZr28VoKQ1ZYU8AmUhm7/yARJxzTtiKxc36WjRzpDuOjPAhmvp1SX6Awb+FNov8PoKqXFeNQoVkN+wS0dudswiFZJTsobeZFPEklkd1j+6yqzC8RgO8tmkqVTPTMo238GEFX7IdTDi9Po5yaBbvKr5Kn3c6ytn2g35CRfqbinm5hQWSKCo9JM+epFY9cApK6y61Ax1kluWBx7qWjUSYktJkS4ZjpF4=";

    public static void main(String[] args) throws DecoderException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        /*Crypto crypto = new Crypto();
        Cryptography cryptography = crypto.getCryptography();
        cryptography.performCryptography(crypto.getCryptographyAction());*/
        try {
            String type = "RES";
            switch (type) {
                case "REQ": {
                    System.out.println(decrypt(requestPayload, AES_KEY));
                    break;
                }
                case "RES": {
                    System.out.println(decrypt(responsePayload, AES_KEY));
                    break;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static String encrypt(String payload, String AES_KEY) throws Exception {
        //this.AES_KEY=AES_KEY;
        //System.out.println("this.AES_KEY  ::  "+this.AES_KEY.length());
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(payload.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    static String decrypt(String payload, String AES_KEY) throws Exception {
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        //byte[] decryptedBytes = cipher.doFinal(payload.getBytes());
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(payload));
        return new String(decryptedBytes);
    }
}
