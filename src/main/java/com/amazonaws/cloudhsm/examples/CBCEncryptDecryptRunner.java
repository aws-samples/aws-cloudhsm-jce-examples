/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Demonstrate how to encrypt and decrypt data using AES and DES keys
 * with CBC mode. To generate the IV, FIPS compliant AES-CTR-DRBG is used.
 */
public class CBCEncryptDecryptRunner {

    public static void main(final String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        System.out.println("Using AES to test encrypt/decrypt in CBC mode");
        String transformation = "AES/CBC/PKCS5Padding";
        Key key = SymmetricKeys.generateAESKey(256, "AESCBC Test");
        byte[] iv = generateFipsCompliantIV(16);
        encryptDecrypt(transformation, key, iv);

        System.out.println("Using DES to test encrypt/decrypt in CBC mode");
        transformation = "DESede/CBC/PKCS5Padding";
        key = SymmetricKeys.generateDESKey("DESCBC Test");
        iv = generateFipsCompliantIV(8);
        encryptDecrypt(transformation, key, iv);
    }

    /**
     * Encrypt and decrypt a string using the transformation/key/iv supplied by the caller.
     *
     * @param transformation
     * @param key
     * @param iv
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void encryptDecrypt(String transformation, Key key, byte[] iv)
            throws NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException {

        String plainText = "This is a sample plain text message!";
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt the string and display the base64 cipher text
        Cipher encryptCipher = Cipher.getInstance(transformation, "Cavium");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF-8"));

        System.out.println("Base64 cipher text = " + Base64.getEncoder().encodeToString(cipherText));

        // Decrypt the cipher text and display the original string
        Cipher decryptCipher = Cipher.getInstance(transformation, "Cavium");
        decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedText = decryptCipher.doFinal(cipherText);

        System.out.println("Decrypted text = " + new String(decryptedText, "UTF-8"));
    }

    /**
     * Generate random bytes using FIPS compliant AES-CTR-DRBG.
     * These bytes will be used for the initialization vector.
     *
     * @param ivSizeinBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] generateFipsCompliantIV(final int ivSizeinBytes)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom sr;

        sr = SecureRandom.getInstance("AES-CTR-DRBG", "Cavium");
        byte[] iv = new byte[ivSizeinBytes];
        sr.nextBytes(iv);
        return iv;
    }
}
