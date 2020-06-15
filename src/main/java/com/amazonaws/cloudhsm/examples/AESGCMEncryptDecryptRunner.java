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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

/**
 * This sample demonstrates how to encrypt data with AES GCM. It shows where the IV is generated
 * and how to pass authenticated tags to the encrypt and decrypt functions.
 */
public class AESGCMEncryptDecryptRunner {

    public static void main(String[] z) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate a new AES Key to use for encryption.
        Key key = SymmetricKeys.generateAESKey(256, "AesGcmTest");

        // Generate some random data to encrypt
        byte[] plainText = new byte[1024];
        Random r = new Random();
        r.nextBytes(plainText);

        // Encrypt the plaintext with authenticated data.
        String aad = "16 bytes of data";
        List<byte[]> result = encrypt(key, plainText, aad.getBytes());

        // Store the HSM's IV and the ciphertext.
        byte[] iv = result.get(0);
        byte[] cipherText = result.get(1);

        // The IV will have 12 bytes of data and a 4 byte counter.
        for (int i=0; i<iv.length; i++) {
            System.out.printf("%02X", iv[i]);
        }
        System.out.printf("\n");

        // Decrypt the ciphertext.
        byte[] decryptedText = decrypt(key, cipherText, iv, aad.getBytes());
        assert(java.util.Arrays.equals(plainText, decryptedText));
        System.out.println("Successful decryption");
    }

    /**
     * Encrypt some plaintext and authentication data using the GCM cipher mode.
     * @param key
     * @param plainText
     * @param aad
     * @return List of byte[] containing the IV and cipherText
     */
    public static List<byte[]> encrypt(Key key, byte[] plainText, byte[] aad) {
        try {
            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", "Cavium");
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            encCipher.updateAAD(aad);
            encCipher.update(plainText);
            byte[] ciphertext = encCipher.doFinal();

            // The IV is generated inside the HSM. It is needed for decryption, so
            // both the ciphertext and the IV are returned.
            return Arrays.asList(encCipher.getIV(), ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt the ciphertext using the HSM supplied IV and the user supplied tag data.
     * @param key
     * @param cipherText
     * @param iv
     * @param aad
     * @return byte[] of the decrypted ciphertext.
     */
    public static byte[] decrypt(Key key, byte[] cipherText, byte[] iv, byte[] aad) {
        Cipher decCipher;
        try {
            // Only 128 bit tags are supported
            GCMParameterSpec gcmSpec = new GCMParameterSpec(16 * Byte.SIZE, iv);

            decCipher = Cipher.getInstance("AES/GCM/NoPadding", "Cavium");
            decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            decCipher.updateAAD(aad);
            return decCipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
