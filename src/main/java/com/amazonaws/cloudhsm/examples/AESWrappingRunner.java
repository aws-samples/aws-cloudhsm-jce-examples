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
import java.security.MessageDigest;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * This sample demonstrates wrapping a key out of CloudHSM and unwrapping a key into CloudHSM using
 * the AESWrap algorithm.
 */
public class AESWrappingRunner {

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

        // Generate a new AES Key in CloudHSM to wrap or unwrap extractable keys.
        SecretKey aesWrappingKey = (SecretKey) SymmetricKeys.generateAESKey(256, "AesWrapSample");

        // Generate a new key as a payload for wrap and unwrap operations. This
        // sample uses an HMAC key.
        SecretKey payloadKey = (SecretKey) SymmetricKeys.generateHmacKey("AesWrapPayloadSample");

        // Run the samples.
        aesWrapNoPadding(aesWrappingKey, payloadKey);
        aesWrapZeroPadding(aesWrappingKey, payloadKey);
        aesWrapPkcs5Padding(aesWrappingKey, payloadKey);

        // Remove sample keys from CloudHSM.
        aesWrappingKey.destroy();
        payloadKey.destroy();
    }

    /**
     * This method demonstrates "AESWrap/ECB/NoPadding"
     *
     * @param aesWrappingKey AES key for wrapping
     * @param payloadKey     Some payload-key to be wrapped
     */
    private static void aesWrapNoPadding(Key aesWrappingKey, Key payloadKey) throws Exception {
        // Create an AESWrap no padding cipher from the CloudHSM provider.
        Cipher cipher = Cipher.getInstance("AESWrap/ECB/NoPadding", CloudHsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode.
        cipher.init(Cipher.WRAP_MODE, aesWrappingKey);

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an AESWrap no padding cipher for unwrapping.
        cipher.init(Cipher.UNWRAP_MODE, aesWrappingKey);

        // Unwrap the key we just wrapped.
        Key unwrappedKey = cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM,
            Cipher.SECRET_KEY);

        // Demonstrate that the unwrapped key matches the original payload key
        // by computing an HMAC digest with each key and comparing the result.
        // Then remove the new unwrapped key from CloudHSM.
        try {
            assert (
                MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "AESWrap no padding"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "AESWrap no padding")));
            System.out.println(
                "Verified wrap and unwrap with AESWrap/ECB/NoPadding using the CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }

    /**
     * This method demonstrates "AESWrap/ECB/ZeroPadding"
     *
     * @param aesWrappingKey AES key for wrapping
     * @param payloadKey     Some payload-key to be wrapped
     */
    private static void aesWrapZeroPadding(Key aesWrappingKey, Key payloadKey) throws Exception {
        // Create an AESWrap zero padding cipher from the CloudHSM provider.
        Cipher cipher = Cipher.getInstance("AESWrap/ECB/ZeroPadding",
            CloudHsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode.
        cipher.init(Cipher.WRAP_MODE, aesWrappingKey);

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an AESWrap zero padding cipher for unwrapping.
        cipher.init(Cipher.UNWRAP_MODE, aesWrappingKey);

        // Unwrap the key we just wrapped.
        Key unwrappedKey = cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM,
            Cipher.SECRET_KEY);

        // Confirm our wrapped-then-unwrapped key matches the original payload
        // key. Then remove the new unwrapped key from CloudHSM.
        try {
            assert (
                MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "AESWrap zero padding"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "AESWrap zero padding")));
            System.out.println(
                "Verified wrap and unwrap with AESWrap/ECB/ZeroPadding using the CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }

    /**
     * This method demonstrates "AESWrap/ECB/PKCS5Padding"
     *
     * @param wrappingKey AES key for wrapping
     * @param payloadKey  Some payload-key to be wrapped
     */
    private static void aesWrapPkcs5Padding(Key wrappingKey, Key payloadKey) throws Exception {
        // Create an AESWrap PKCS5 padding cipher from the CloudHSM provider.
        Cipher cipher = Cipher.getInstance("AESWrap/ECB/PKCS5Padding",
            CloudHsmProvider.PROVIDER_NAME);

        // Initialize the cipher in wrap mode.
        cipher.init(Cipher.WRAP_MODE, wrappingKey);

        // Wrap the payload key.
        byte[] wrappedKey = cipher.wrap(payloadKey);

        // Initialize an AESWrap PKCS5 padding cipher for unwrapping.
        cipher.init(Cipher.UNWRAP_MODE, wrappingKey);

        // Unwrap the key we just wrapped.
        Key unwrappedKey = cipher.unwrap(wrappedKey, SAMPLE_HMAC_ALGORITHM,
            Cipher.SECRET_KEY);

        // Confirm our wrapped-then-unwrapped key matches the original payload
        // key. Then remove the new unwrapped key from CloudHSM.
        try {
            assert (
                MessageDigest.isEqual(
                    hmacDigest(payloadKey, SAMPLE_HMAC_ALGORITHM, "AESWrap PKCS padding"),
                    hmacDigest(unwrappedKey, SAMPLE_HMAC_ALGORITHM, "AESWrap PKCS padding")));
            System.out.println(
                "Verified wrap and unwrap with AESWrap/ECB/PKCS5Padding using the CloudHSM provider");
        } finally {
            ((Destroyable) unwrappedKey).destroy();
        }
    }
}
