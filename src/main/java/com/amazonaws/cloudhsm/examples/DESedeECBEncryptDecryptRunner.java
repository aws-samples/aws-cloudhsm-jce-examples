/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * This sample demonstrates how to encrypt data with DESede ECB.
 */
public class DESedeECBEncryptDecryptRunner {

    public static void main(String[] z) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate a new DES Key to use for encryption.
        Key key = SymmetricKeys.generateDESKey("DesEcbTest");

        // Generate some random data to encrypt
        byte[] plainText = new byte[1024];
        Random r = new Random();
        r.nextBytes(plainText);

        // Encrypt the plaintext
        byte[] cipherText = encrypt(key, plainText);
        // Decrypt the ciphertext.
        byte[] decryptedText = decrypt(key, cipherText);
        assert(java.util.Arrays.equals(plainText, decryptedText));
        System.out.println("Successful decryption");
    }

    /**
     * Encrypt some plaintext using the DESede ECB cipher mode.
     * @param key
     * @param plainText
     * @return byte[] containing encrypted data
     */
    public static byte[] encrypt(Key key, byte[] plainText) {
        try {
            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding", "Cavium");
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            return encCipher.doFinal(plainText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt the ciphertext using the DESede ECB cipher mode.
     * @param key
     * @param cipherText
     * @return byte[] of the decrypted ciphertext.
     */
    public static byte[] decrypt(Key key, byte[] cipherText) {
        Cipher decCipher;
        try {
            decCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding", "Cavium");
            decCipher.init(Cipher.DECRYPT_MODE, key);
            return decCipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
