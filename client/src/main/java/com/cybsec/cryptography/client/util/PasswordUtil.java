package com.cybsec.cryptography.client.util;

import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;

public final class PasswordUtil {
    private PasswordUtil() {}

    /**
     * Checks if a char[] is null, empty, or contains only whitespace characters.
     * @param chars character array
     * @return true if char array is null, empty or whitespaces, else, returns false
     */
    public static boolean isBlank(char[] chars) {
        if (chars == null) {
            return true;
        }
        for (char c : chars) {
            if (!Character.isWhitespace(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if a char[] is null or empty (but not whitespace).
     * @param chars character array
     * @return true if char array is null or empty, else, returns false
     */
    public static boolean isEmpty(char[] chars) {
        return chars == null || chars.length == 0;
    }

    /**
     * Secure, constant-time comparison of two char[] values.
     * Used for comparing sensitive data and prevent timing attacks.
     * @param a first char[]
     * @param b second char[]
     * @return true if both char arrays match, else, returns false
     */
    /*
    Usually when matching is done char by char, as soon as an unmatching char is found, the function returns false.
    This results in different failure timings depending on how many chars matched successfully.
    And this can lead an attacker over time to guess the correct match by passing different inputs and measuring response times.
    This function solves that.
    The XOR (^) gives 0 if the compared chars are equal and 1 otherwise.
    And the Bitwise OR (|) will hold 1 if any one of the compared inputs is 1.
    Since {result = result | (a[i] ^ b[i])} is put in loop, the matching takes same amount of time no matter how many mismatches occur,
    and the result will hold 1 even if a single mismatch occurred anywhere in the entire array.
    */
    public static boolean constantTimeEquals(char[] a, char[] b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Secure, constant-time comparison of two byte[] values.
     * Used for comparing sensitive data and prevent timing attacks.
     * @param a first byte[]
     * @param b second byte[]
     * @return true if both byte arrays match, else, returns false
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Fetches sensitive data from stored environment variable as char[] and clears the String reference.
     * Returns null if environment variable doesn't exist.
     * @param envVar Environment variable name
     * @return Data as char[]
     */
    public static char[] getFromEnv(String envVar) {
        if (StringUtils.isBlank(envVar)) {
            throw new IllegalArgumentException("Invalid environment variable");
        }
        String value = System.getenv(envVar);
        if (value == null) {
            return null;
        }
        char[] chars = value.toCharArray();
        // Clear the String reference to prevent exploiting stored sensitive string
        value = null;
        envVar = null;
        return chars;
    }

    /**
     * Converts a sensitive String to char[] and clears the original String reference.
     * Use ONLY when input arrives as a String and cannot be avoided (e.g., password fields).
     * @param input string to convert
     * @return character array
     */
    public static char[] toCharArray(String input) {
        if (StringUtils.isBlank(input)) {
            return null;
        }
        char[] chars = input.toCharArray();
        // Remove reference to immutable String (to prevent exploiting stored sensitive string)
        input = null;
        return chars;
    }

    /**
     * Securely wipes (zeros out) the char[] from memory.
     * Call this IMMEDIATELY after you're done using the password.
     * @param chars characters to wipe
     */
    public static void wipe(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\u0000'); // null character
        }
    }

    /**
     * Securely wipes (zeros out) the byte[] from memory.
     * Can be used for key material.
     * @param bytes bytes to wipe
     */
    public static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Clones a char[] defensively. Useful for storing internal copies.
     * @param chars char[] to copy
     * @return cloned char[]
     */
    public static char[] clone(char[] chars) {
        if (chars == null) {
            return null;
        }
        return Arrays.copyOf(chars, chars.length);
    }

    /**
     * Clones a byte[] defensively. Useful for storing internal copies.
     * @param bytes byte[] to copy
     * @return cloned byte[]
     */
    public static byte[] clone(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return Arrays.copyOf(bytes, bytes.length);
    }
}
