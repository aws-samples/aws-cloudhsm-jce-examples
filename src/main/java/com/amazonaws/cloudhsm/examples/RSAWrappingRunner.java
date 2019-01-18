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
import com.cavium.key.*;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;

import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Arrays;

/**
 * This sample demonstrates how to use RSA to wrap and unwrap a key into and out of the HSM.
 */
public class RSAWrappingRunner {
    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Wrapping keys must be persistent.
        KeyPair wrappingKeyPair = new AsymmetricKeys().generateRSAKeyPairWithParams(2048, "RSA Wrapping Test", true, true);

        // Extractable keys must be marked extractable.
        Key extractableKey = generateExtractableKey(256, "Extractable key to wrap", false);

        try {
            // Using the wrapping keypair, wrap and unwrap the extractable key with OAEP wrapping.
            rsaOAEPWrap(wrappingKeyPair.getPublic(), wrappingKeyPair.getPrivate(), extractableKey);

            // Using the wrapping keypair, wrap and unwrap the extractable key with RSA AES wrapping.
            rsaAesWrap(wrappingKeyPair.getPublic(), wrappingKeyPair.getPrivate(), extractableKey);

            // Clean up the keys.
            Util.deleteKey((CaviumKey) wrappingKeyPair.getPrivate());
            Util.deleteKey((CaviumKey) extractableKey);
        } catch (CFM2Exception ex) {
            ex.printStackTrace();
            System.out.printf("Failed to delete key handles: %d\n", ((CaviumKey) wrappingKeyPair.getPrivate()).getHandle());
        }
    }

    /**
     * Using the wrapping keypair, wrap and unwrap the extractable key with RSAAESWrap.
     *
     * @param wrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void rsaAesWrap(Key wrappingKey, Key unwrappingKey, Key extractableKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSAAESWrap", "Cavium");
        cipher.init(Cipher.WRAP_MODE, wrappingKey);

        // Wrap the extractable key using the wrappingKey.
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using the SunJCE.
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Compare the two keys.
        // Notice that extractable keys can be exported from the HSM using the .getEncoded() method.
        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using RSAAES inside the HSM to wrap and unwrap: %s\n", Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));
    }

    /**
     * Using the wrapping keypair, wrap and unwrap the extractable key with OAEP.
     * Use both the Cavium provider and the SunJCE to demonstrate compatibility. Note this works because the
     * wrapping keypair is marked "extractable". This allows the SunJCE to extract the unwrapping key before
     * performing the operation.
     *
     * @param wrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void rsaOAEPWrap(Key wrappingKey, Key unwrappingKey, Key extractableKey)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "Cavium");
        cipher.init(Cipher.WRAP_MODE, wrappingKey, spec);

        // Wrap the extractable key using the wrappingKey.
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Create a SunJCE provider to unwrap the key, exposing the PKCS#5 padding.
        Cipher sunCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "SunJCE");

        // Unwrap using the SunJCE.
        sunCipher.init(Cipher.UNWRAP_MODE, unwrappingKey, spec);
        Key unwrappedExtractableKey = sunCipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Compare the two keys.
        // Notice that extractable keys can be exported from the HSM using the .getEncoded() method.
        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using OAEP in the HSM and SunJCE to wrap and unwrap: %s\n", Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));
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
}