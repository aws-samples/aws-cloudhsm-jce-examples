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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.security.util.KeyUtil;

/**
 * Demonstrate how to generate keys
 */
public class ECDHOperationsRunner {

    public static void main(final String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());

            //Add another provider. SunEC is used as an example here.
            Security.addProvider(new sun.security.ec.SunEC());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        final String CURVE_ID = "secp256r1";

        //There is a EC key pair in HSM
        KeyPairGenerator keyPairGenA = KeyPairGenerator.getInstance("EC", "Cavium");
        keyPairGenA.initialize(new ECGenParameterSpec(CURVE_ID));
        KeyPair keyPairA = keyPairGenA.generateKeyPair();

        //There is a EC key pair externally. Lets say with SunEC provider.
        KeyPairGenerator keyPairGenB = KeyPairGenerator.getInstance("EC", "SunEC");
        keyPairGenB.initialize(new ECGenParameterSpec(CURVE_ID)); //We need to use the same Curve on both the sides.
        KeyPair keyPairB = keyPairGenB.generateKeyPair();

        //Each side computes the shared key using its own private key and public key from the other side

        //Use keyPairA's private key and keyPairB's public key to generate a secret.
        //This has to be Cavium provider as keyPairA's private key is in HSM and non-extractable by default.
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH", "Cavium");
        keyAgreementA.init(keyPairA.getPrivate());
        keyAgreementA.doPhase(keyPairB.getPublic(), true);
        byte[] secretXBytes = keyAgreementA.generateSecret();

        //Use keyPairB's private key and keyPairA's public key to generate a secret.
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH", "SunEC");
        keyAgreementB.init(keyPairB.getPrivate());
        keyAgreementB.doPhase(keyPairA.getPublic(), true);
        byte[] secretYBytes = keyAgreementB.generateSecret();

        //These byte[] should be identical.
        System.out.println("Secret X: Length = " + secretXBytes.length +", Base64 = " + Base64.getEncoder().encodeToString(secretXBytes));
        System.out.println("Secret Y: Length = " + secretYBytes.length +", Base64 = " + Base64.getEncoder().encodeToString(secretYBytes));

        //Each side can now convert this into a secret key.
        SecretKey keyA = new SecretKeySpec(KeyUtil.trimZeroes(secretXBytes), "TlsPremasterSecret");
        SecretKey keyB = new SecretKeySpec(KeyUtil.trimZeroes(secretYBytes), "TlsPremasterSecret");

        if(Arrays.equals(keyA.getEncoded(), keyB.getEncoded())) {
            System.out.println("Secret Keys are same!");
        } else {
            System.out.println("Secret Keys are different!");
        }
    }
}
