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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Demonstrate basic RSA operations.
 */
public class RSAOperationsRunner {
    /**
     * Encrypt plainText using the passed transformation.
     * Supported transformations are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param transformation
     * @param key
     * @param plainText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(String transformation, Key key, byte[] plainText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher encCipher = Cipher.getInstance(transformation, "Cavium");
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        return encCipher.doFinal(plainText);
    }

    /**
     * Decrypt cipherText using the passed transformation.
     * Supported transformations are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param transformation
     * @param key
     * @param cipherText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt(String transformation, Key key, byte[] cipherText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher decCipher = Cipher.getInstance(transformation, "Cavium");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        return decCipher.doFinal(cipherText);
    }

    /**
     * Sign a message using the passed signing algorithm.
     * Supported signature types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param key
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] sign(byte[] message, PrivateKey key, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, "Cavium");
        sig.initSign(key);
        sig.update(message);
        return sig.sign();
    }

    /**
     * Verify the signature of a message.
     * Supported signature types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param signature
     * @param publicKey
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, "Cavium");
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(signature);
    }

    public static void main(final String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String plainText = "This is a sample Plain Text Message!";
        String transformation = "RSA/ECB/OAEPPadding";

        KeyPair kp = new AsymmetricKeys().generateRSAKeyPair(2048, "rsa test");

        System.out.println("Performing RSA Encryption Operation");
        byte[] cipherText = null;
        cipherText = encrypt(transformation, kp.getPublic(), plainText.getBytes("UTF-8"));

        System.out.println("Encrypted plaintext = " + Base64.getEncoder().encodeToString(cipherText));

        byte[] decryptedText = decrypt(transformation, kp.getPrivate(), cipherText);
        System.out.println("Decrypted text = " + new String(decryptedText, "UTF-8"));

        String signingAlgorithm = "SHA512withRSA/PSS";
        byte[] signature = sign(plainText.getBytes("UTF-8"), kp.getPrivate(), signingAlgorithm);
        System.out.println("Plaintext signature = " + Base64.getEncoder().encodeToString(signature));

        if (verify(plainText.getBytes("UTF-8"), signature, kp.getPublic(), signingAlgorithm)) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature is invalid!");
        }
    }
}
