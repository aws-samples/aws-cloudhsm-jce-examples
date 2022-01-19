/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.EcParams;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * This sample demonstrates how one can perform the following operations while leveraging the
 * Custom Key Attributes feature:  Key Generation, and Key Import.
 */
public class KeyAttributesRunner {

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.err.println(ex);
            return;
        }

        generateEcKeyPair();
        importAesKey();
    }

    /*
     * Demonstrate the generation of an EC key pair while using Custom Key Attributes.
     */
    private static void generateEcKeyPair() throws Exception {
        System.out.println("Generate EC Key Pair using CloudHsm Attributes\n");
        final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);

        // Demonstrate the construction of a KeyAttributesMap for the public key by first
        // instantiating the class and adding key-value pairs, much like would be done via
        // Map objects.
        final String ecPublicKeyLabel = "EC Public Key";

        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, ecPublicKeyLabel);
        publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, EcParams.EC_CURVE_PRIME256);

        // Demonstrate the construction of a KeyAttributesMap for the private key using
        // the Builder pattern.  Note how method chaining is supported.
        final String ecPrivateKeyLabel = "EC Private Key";

        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, ecPrivateKeyLabel)
                .build();

        // Instantiate KeyPairAttributesMap for use during generation of the EC key pair.
        // Note how the Builder pattern is used to construct a KeyPairAttributesMap from
        // the previous public and private key attributes maps.
        final KeyPairAttributesMap spec = new KeyPairAttributesMapBuilder()
                .withPublic(publicKeyAttrsMap)
                .withPrivate(privateKeyAttrsMap)
                .build();
        keyPairGen.initialize(spec);
        final KeyPair keyPair = keyPairGen.generateKeyPair();
        System.out.println("EC Key Pair generated\n");
    }

    /*
     * Demonstrate the import of an externally-generated AES key while using Custom Key
     * Attributes.
     */
    private static void importAesKey() throws Exception {
        System.out.println("Importing AES Key into the HSM using CloudHsm Attributes\n");

        final int aesKeySize = 256;

        // Generate a key using the SunJCE provider.
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
        keyGen.init(aesKeySize);
        final SecretKey sk = keyGen.generateKey();

        // Import the key into the HSM.
        final String genericSecretKeyLabel = "AES Key";

        // Instantiate KeyAttributesMap for use during import of the Generic
        // Secret key.
        final KeyAttributesMap keyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, genericSecretKeyLabel)
                .put(KeyAttribute.VALUE, sk.getEncoded())
                .build();

        SecretKeyFactory factory = SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        SecretKey cloudHsmKey = factory.generateSecret(keyAttrsMap);
        System.out.println("AES Key imported\n");
    }
}
