/*
 * Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Generate an EdDSA Key Pair using BouncyCastle then import it into the HSM
 * This example shows importing EdDSA keys in two methods:
 * 1. through encoded key specs
 * 2. Using the Key Attributes
 */
public class EdDSAImportKey {
    private static String helpString = "EdDSAImportKey\n" +
            "Generate an Ed25519 Key Pair using BouncyCastle then import it into the HSM\n";

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new CloudHsmProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // First, generate a keypair with BouncyCastle to test import
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator bcGenerator =
                KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair bcKeyPair = bcGenerator.generateKeyPair();
        System.out.println("Generated Ed25519 key pair with BouncyCastle");

        PrivateKey bcPrivateKey = bcKeyPair.getPrivate();
        PublicKey bcPublicKey = bcKeyPair.getPublic();

        // Method 1: Import the private key using PKCS8EncodedKeySpec and the public key with X509EncodedKeySpec
        // Keys will be generated with default attributes
        // Reference: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-attributes_5.html
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bcPublicKey.getEncoded());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bcPrivateKey.getEncoded());
        KeyFactory keyFactory =
                KeyFactory.getInstance("Ed25519", CloudHsmProvider.PROVIDER_NAME);

        
        PublicKey hsmPublicKey = keyFactory.generatePublic(publicKeySpec);
        System.out.println("Imported Ed25519 public key into CloudHSM via X509EncodedKeySpec");
        PrivateKey hsmPrivateKey = keyFactory.generatePrivate(privateKeySpec);
        System.out.println("Imported Ed25519 private key into CloudHSM via PKCS8EncodedKeySpec");

        // Method 2: Import the Key Pair using KeyAttributesMap in order to specify custom key
        // attributes such as setting TOKEN to false.
        
        // Set attributes for Ed25519 public key
        KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, "ImportedPublicKey");
        publicKeyAttrsMap.put(KeyAttribute.EC_POINT, bcPublicKey.getEncoded());
        publicKeyAttrsMap.put(KeyAttribute.TOKEN, false);
        PublicKey hsmPublicKeyWithAttributes = (PublicKey) keyFactory.generatePublic(publicKeyAttrsMap);
        // Set attributes for Ed25519 private key
        KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMap();
        privateKeyAttrsMap.put(KeyAttribute.LABEL, "ImportedPrivateKey");
        privateKeyAttrsMap.put(KeyAttribute.VALUE, bcPrivateKey.getEncoded());
        privateKeyAttrsMap.put(KeyAttribute.TOKEN, false);
        PrivateKey hsmPrivateKeyWithAttributes = (PrivateKey) keyFactory.generatePrivate(privateKeyAttrsMap);

        KeyPair hsmKeyPairWithAttributes = new KeyPair(hsmPublicKeyWithAttributes, hsmPrivateKeyWithAttributes);
        System.out.println("Imported Ed25519 KeyPair using KeyAttributes");

        // Verify the imported keys work by signing and verifying, cross provider
        String plainText = "This is a test message for imported Ed25519 keys!";
        String signingAlgorithm = "Ed25519";
        byte[] signature = EdDSAOperationsRunner.sign(plainText.getBytes("UTF-8"), hsmPrivateKeyWithAttributes, signingAlgorithm);
        System.out.println("Plaintext signature = " + Base64.getEncoder().encodeToString(signature));

        Signature bcVerifier = Signature.getInstance(signingAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        bcVerifier.initVerify(bcPublicKey);
        bcVerifier.update(plainText.getBytes("UTF-8"));
        if (bcVerifier.verify(signature)){
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature is invalid!");
        }
    }

    private static void help() {
        System.out.println(helpString);
    }
}
