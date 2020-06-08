/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * This sample demonstrates how to use AESWrap to wrap and unwrap a key into and out of the HSM.
 */
public class AESWrappingRunner {
    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        /* We need an AES key to wrap and unwrap our extractable keys. */
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey sunJceWrappingKey = keyGen.generateKey();

        /* Import this AES key into the HSM so we can wrap in the HSM and unwrap locally */
        CaviumKey hsmWrappingKey = importWrappingKey(sunJceWrappingKey);
        Util.persistKey(hsmWrappingKey);

        // Extractable keys must be marked extractable.
        Key extractableKey = generateExtractableKey(256, "Test Extractable Key", false);

        try {

            System.out.printf("\nOriginal key before wrapping:\n %s\n",
                                Base64.getEncoder().encodeToString(extractableKey.getEncoded()));

            // Example to demonstrate wrap and unwrap with "AESWrap/ECB/NoPadding"
            wrapWithNoPad(hsmWrappingKey, sunJceWrappingKey, extractableKey);

            // Example to demonstrate wrap and unwrap with "AESWrap/ECB/PKCS5Padding"
            wrapWithPkcs5Pad(hsmWrappingKey, extractableKey);

            // Example to demonstrate wrap and unwrap with "AESWrap/ECB/ZeroPadding"
            wrapWithZeroPad(hsmWrappingKey, extractableKey);

            // Clean up the keys.
            Util.deleteKey((CaviumKey) hsmWrappingKey);
            Util.deleteKey((CaviumKey) extractableKey);

        } catch (CFM2Exception ex) {
            ex.printStackTrace();
            System.out.printf("Failed to delete key handles: %d\n", ((CaviumKey) hsmWrappingKey).getHandle());
        }
    }

    /**
     * The method demonstrates "AESWrap/ECB/NoPadding" by wrapping a key with Cavium provider
     * and unwrapping the key with SunJCE provider.
     * @param wrappingKey
     * @param sunJceWrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void wrapWithNoPad(Key hsmWrappingKey, Key sunJceWrappingKey, Key extractableKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AESWrap/ECB/NoPadding", "Cavium");
        cipher.init(Cipher.WRAP_MODE, hsmWrappingKey);

        // Wrap the extractable key using the wrappingKey
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using hsm
        cipher.init(Cipher.UNWRAP_MODE, hsmWrappingKey);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Compare original key with HSM unwrapped key
        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using the HSM to wrap and unwrap with AESWrap/ECB/NoPadding:\n %s\n",
                            Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));

    }

    /**
     * This method demonstrates "AESWrap/ECB/PKCS5Padding" by wrapping and unwrapping a key using HSM.
     * @param hsmWrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void wrapWithPkcs5Pad(Key hsmWrappingKey, Key extractableKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AESWrap/ECB/PKCS5Padding", "Cavium");
        cipher.init(Cipher.WRAP_MODE, hsmWrappingKey);

        // Wrap the extractable key using the wrappingKey
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using the HSM
        cipher.init(Cipher.UNWRAP_MODE, hsmWrappingKey);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Compare the two keys
        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using the HSM to wrap and unwrap with AESWrap/ECB/PKCS5Padding:\n %s\n",
                            Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));
    }

    /**
     * This method demonstrates "AESWrap/ECB/ZeroPadding" by wrapping and unwrapping a key using HSM.
     * @param hsmWrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void wrapWithZeroPad(Key hsmWrappingKey, Key extractableKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AESWrap/ECB/ZeroPadding", "Cavium");
        cipher.init(Cipher.WRAP_MODE, hsmWrappingKey);

        // Wrap the extractable key using the wrappingKey
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using the HSM
        cipher.init(Cipher.UNWRAP_MODE, hsmWrappingKey);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Compare the two keys
        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using the HSM to wrap and unwrap with AESWrap/ECB/ZeroPadding:\n %s\n",
                            Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));
    }

    /**
     * Generate an extractable key that can be toggled persistent.
     * AES wrapping keys are required to be persistent. The keys being wrapped can be persistent or session keys.
     *
     * @param keySizeInBits
     * @param keyLabel
     * @return CaviumKey that is extractable and persistent.
     */
    private static Key generateExtractableKey(int keySizeInBits, String keyLabel, boolean isPersistent) {
        boolean isExtractable = true;

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");

            CaviumAESKeyGenParameterSpec aesSpec = new CaviumAESKeyGenParameterSpec(keySizeInBits, keyLabel, isExtractable, isPersistent);
            keyGen.init(aesSpec);
            SecretKey aesKey = keyGen.generateKey();

            return aesKey;

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            if (CFM2Exception.isAuthenticationFailure(e)) {
                System.out.println("Detected invalid credentials");
            } else if (CFM2Exception.isClientDisconnectError(e)) {
                System.out.println("Detected daemon network failure");
            }

            e.printStackTrace();
        }

        return null;
    }

    /**
     * Import a local key into the HSM.
     * This method will create a new RSA KeyPair in CloudHSM and wrap the local key with the public key.
     * Then the wrapped bytes will be unwrapped inside CloudHSM using the private key.
     * @param wrappingKey
     * @return
     * @throws Exception
     */
    private static CaviumKey importWrappingKey(SecretKey wrappingKey) throws Exception {
        KeyPair wrappingKeyPair = new AsymmetricKeys().generateRSAKeyPairWithParams(2048, "RSA Wrapping Test", true, true);

        // Wrap the key and delete it.
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher wrapCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "SunJCE");
        wrapCipher.init(Cipher.WRAP_MODE, wrappingKeyPair.getPublic(), spec);
        byte[] wrappingKeyWrappedBytes = wrapCipher.wrap(wrappingKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "Cavium");
        cipher.init(Cipher.UNWRAP_MODE, wrappingKeyPair.getPrivate());
        Key caviumWrappingKey = cipher.unwrap(wrappingKeyWrappedBytes, "AES", Cipher.SECRET_KEY);

        // The keypair is no longer needed. We have the wrapping key in the HSM and locally.
        Util.deleteKey((CaviumKey)wrappingKeyPair.getPrivate());
        return (CaviumKey) caviumWrappingKey;
    }
}
