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

import static com.amazonaws.cloudhsm.examples.HmacUtil.hmacDigest;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * This sample demonstrates wrapping a key out of CloudHSM and unwrapping a key into CloudHSM using
 * various RSA algorithm variants.
 */
public class RSAWrappingRunner {

    private static final String SAMPLE_HMAC_ALGORITHM = "HmacSHA1";

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate an RSA key pair for wrapping keys.
        KeyPair wrappingKeyPair = new AsymmetricKeys().generateRSAKeyPair(2048, "RsaWrapSample");

        // Generate a new payload key to wrap and unwrap. This sample uses an
        // HMAC key.
        SecretKey payloadKey = (SecretKey) SymmetricKeys.generateHmacKey("RsaWrapPayloadSample");

        // Run the samples.
        rsaOaepWrap(wrappingKeyPair, payloadKey);
        rsaAesWrap(wrappingKeyPair, payloadKey);

        // Remove sample keys from CloudHSM.
        ((Destroyable) wrappingKeyPair.getPublic()).destroy();
        ((Destroyable) wrappingKeyPair.getPrivate()).destroy();
        ((Destroyable) payloadKey).destroy();
    }

    /**
     * This method demonstrates "RSA/ECB/OAEPWithSHA-256ANDMGF1Padding" wrap and unwrap.
     *
     * @param wrappingKeyPair RSA key pair for wrapping
     * @param payloadKey      Some payload-key to be wrapped
     */
    private static void rsaOaepWrap(KeyPair wrappingKeyPair, Key payloadKey) throws Exception {
        // Create an RSA OAEP cipher from the CloudHSM provider.
        Cipher cipher = Cipher.getInstance(
            "RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", CloudHsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode with the public key.
        cipher.init(Cipher.WRAP_MODE, wrappingKeyPair.getPublic());

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an RSA OAEP cipher in unwrap mode using the private key.
        cipher.init(Cipher.UNWRAP_MODE, wrappingKeyPair.getPrivate());

        // Unwrap the key we just wrapped.
        Key unwrappedKey = cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM, Cipher.SECRET_KEY);

        // Demonstrate that the unwrapped key matches the original payload key
        // by computing an HMAC digest with each key and comparing the result.
        // Then remove the new unwrapped key from CloudHSM.
        try {
            assert (
                MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "RSA OAEP with CloudHSM"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "RSA OAEP with CloudHSM")));
            System.out.println(
                "Verified wrap and unwrap with RSA/ECB/OAEPWithSHA-256ANDMGF1Padding using the CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }

    /**
     * This method demonstrates "RSAAESWrap" wrap and unwrap.
     *
     * @param wrappingKeyPair RSA key pair for wrapping
     * @param payloadKey      Some payload-key to be wrapped
     */
    private static void rsaAesWrap(KeyPair wrappingKeyPair, Key payloadKey) throws Exception {
        // Create an RSA AES cipher from the CloudHSM provider.
        Cipher cipher = Cipher.getInstance(
            "RSAAESWrap/ECB/OAEPWithSHA-1ANDMGF1Padding", CloudHsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode with the public key.
        cipher.init(Cipher.WRAP_MODE, wrappingKeyPair.getPublic());

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an RSA AES cipher in unwrap mode using the private key.
        cipher.init(Cipher.UNWRAP_MODE, wrappingKeyPair.getPrivate());

        // Unwrap the key we just wrapped.
        Key unwrappedKey = cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM, Cipher.SECRET_KEY);

        // Demonstrate that the unwrapped key matches the original payload key
        // by computing an HMAC digest with each key and comparing the result.
        // Then remove the new unwrapped key from CloudHSM.
        try {
            assert (
                MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "RSA AES with CloudHSM"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "RSA AES with CloudHSM")));
            System.out.println(
                "Verified wrap and unwrap with RSAAESWrap/ECB/OAEPWithSHA-1ANDMGF1Padding using the CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }
}
