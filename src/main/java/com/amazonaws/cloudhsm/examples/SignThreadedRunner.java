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

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumKey;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Random;

/**
 * This sample demonstrates high performance signing. Several threads are used to sign random data blobs. This
 * sample contrasts two methods of signing. The recommended method passes a Key object, where the inefficient method
 * passes a KeyStore and uses getKeyByHandle() to load the key in a loop.
 *
 * This sample relies on implicit login credentials.
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html#java-library-credentials
 */
public class SignThreadedRunner {

    /**
     * WrapKeyLoop is a simple Runnable that takes a key, and issues 200 signing requests with that key.
     * The important part is that this Runnable takes a Key, and not a handle to a key, or a KeyStore. This
     * prevents unnecessary lookup calls to the HSM.
     */
    private static class WrapKeyLoop implements Runnable {
        Key signingKey;

        public WrapKeyLoop(Key key) {
            signingKey = key;
        }

        public void run() {

            // Perform the work using the cached key. This prevents slow lookups on each
            // sign request.
            for(int i=0; i<200; i++) {
                doSign((PrivateKey) signingKey);
            }
        }
    }

    /**
     * WrapKeyLoopInefficient demonstrates a typical pattern that is used with file based keystores. store.getKeyByHandle()
     * is called inside the loop. This pattern is not recommended with CloudHSM due to the network overhead of
     * loading a key over the network.
     */
    private static class WrapKeyLoopInefficient implements Runnable {
        KeyStore store;

        public WrapKeyLoopInefficient(KeyStore store_) {
            store = store_;
        }

        public void run() {

            // Perform the work using the cached key. This prevents slow lookups on each
            // sign request.
            for(int i=0; i<200; i++) {
                try {
                    doSign((PrivateKey) store.getKey("Test Signing Key", null));
                } catch (NoSuchAlgorithmException ex) {
                    ex.printStackTrace();
                    return;
                } catch (UnrecoverableKeyException | KeyStoreException ex) {
                    ex.printStackTrace();
                    return;
                }
            }
        }
    }

    /**
     * The main body of the sample with generate a key pair and then load that keypair from the KeyStore. Production
     * applications will typically load a key from a KeyStore, not generate new keys each time.
     * @param args
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // We need a key pair that can be used to sign the blobs.
        KeyPair pair = generateKeyPair(2048, "Test Signing Key");

        // In a production application we would search the KeyStore for a key that already exists in the HSM.
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("Cavium");
            keyStore.load(null, null);
        } catch (KeyStoreException | CertificateException ex) {
            ex.printStackTrace();
            return;
        } catch (IOException ex) {
            ex.printStackTrace();
            return;
        }

        // Now pull our signing key out of the keystore using the key's label.
        // It is possible to retrieve a key by key handle as well. This method is covered in the KeyUtilitiesRunner.
        Key signingKey = null;
        try {
            signingKey = keyStore.getKey("Test Signing Key", null);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return;
        } catch (UnrecoverableKeyException | KeyStoreException ex) {
            ex.printStackTrace();
            return;
        }

        // Spin up several threads, passing our keystore to each one.
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        for(int i = 0; i < threadCount; i++) {
            // Passing a keystore is not recommended. When working with the keyStore, you will make a lot of
            // round trip requests to the HSM. It is better to make one request for a key, and use that key
            // object throughout the application.
            //
            // threads[i] = new Thread(new WrapKeyLoopInefficient(keyStore));

            // The recommended way to work with keys is by passing key objects. That is because key objects
            // already have metadata loaded, and don't require round trips to the HSM to perform lookups.
            threads[i] = new Thread(new WrapKeyLoop(signingKey));

            threads[i].start();
        }

        System.out.println("Waiting...");
        for(int i = 0; i < threadCount; i++) {
            try {
                threads[i].join();
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }

        System.out.println("Work completed");

        // Clean up after ourselves.
        try {
            Util.deleteKey((CaviumKey) pair.getPrivate());
            Util.deleteKey((CaviumKey) pair.getPublic());
        } catch (CFM2Exception ex) {
            ex.printStackTrace();
            System.out.printf("Failed to delete key handles\n");
        }
    }

    /**
     * Generate 32 bytes of random data, and sign that data using the passed key.
     * @param signingKey
     */
    private static void doSign(PrivateKey signingKey) {
        Random random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);

        try {
            Signature signatureInstance = Signature.getInstance("SHA512withRSA/PSS", "Cavium");
            signatureInstance.initSign(signingKey);
            signatureInstance.update(bytes);
            signatureInstance.sign();
        } catch (SignatureException ex) {
            ex.printStackTrace();
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Generate a key pair that can be used to sign.
     * Only return the private key since this is a demo and that is all we need.
     * @param keySizeInBits
     * @param keyLabel
     * @return KeyPair that is not extractable or persistent.
     */
    private static KeyPair generateKeyPair(int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException {
        KeyPairGenerator keyPairGen;

        // Create and configure a key pair generator
        keyPairGen = KeyPairGenerator.getInstance("rsa", "Cavium");
        keyPairGen.initialize(new CaviumRSAKeyGenParameterSpec(keySizeInBits, new BigInteger("65537"), keyLabel + ":public", keyLabel, false, false));

        // Generate the key pair
        return keyPairGen.generateKeyPair();
    }
}