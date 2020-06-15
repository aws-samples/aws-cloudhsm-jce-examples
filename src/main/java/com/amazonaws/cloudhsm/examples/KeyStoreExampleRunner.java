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

import com.cavium.key.CaviumKey;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Enumeration;
import javax.crypto.KeyGenerator;

/**
 * KeyStoreExampleRunner demonstrates how to enumerate through the KeyStore, and how to find a specific key by label.
 * This example relies on implicit credentials, so you must setup your environment correctly.
 *
 * https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html#java-library-credentials
 */
public class KeyStoreExampleRunner {
    /**
     * Generate and retrieve a key from the keystore.
     * @param argv
     * @throws Exception
     */
    public static void main(String[] argv) throws Exception {
        Security.addProvider(new com.cavium.provider.CaviumProvider());

        KeyStore keyStore = KeyStore.getInstance("Cavium");

        // load() is required to initialize the JCE keystore, however behind the scenes
        // this is a no-op. KeyStore authentication should done using the LoginManager
        // explicitly, or relying on implicit login.
        keyStore.load(null, null);

        // Find and display the amount of keys in the HSM.
        System.out.printf("The KeyStore contains %d keys\n", keyStore.size());

        String keyLabel = "Test KeyStoreLabel";
        generateAesKey(keyLabel);

        if (keyStore.containsAlias(keyLabel)) {
            // If using implicit credentials, the getKeyByHandle() method will kickoff the first authentication attempt.
            // If the session is already authenticated, then getKeyByHandle() will simply reach out to the HSM.
            Key k =  keyStore.getKey(keyLabel, null);
            System.out.printf("Generated key label: %s\n", ((CaviumKey) k).getLabel());
            System.out.printf("Generated key handle: %d\n", ((CaviumKey) k).getHandle());
        }

        // Iterate throught the rest of the KeyStore.
        for(Enumeration<String> entry = keyStore.aliases(); entry.hasMoreElements();) {
            System.out.println(entry.nextElement());
        }
    }

    /**
     * Generate a session AES key that can be pulled from the keyStore.
     * @param keyLabel The label of the key to create.
     * @return The Key object.
     */
    private static Key generateAesKey(String keyLabel) {
        int keySizeBits = 256;
        boolean isExtractable = false;
        boolean isPersistent = false;

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES","Cavium");
            CaviumAESKeyGenParameterSpec aesSpec = new CaviumAESKeyGenParameterSpec(keySizeBits, keyLabel, isExtractable, isPersistent);
            keyGen.init(aesSpec);

            return keyGen.generateKey();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            ex.printStackTrace();
            return null;
        }
    }
}
