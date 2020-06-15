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

import com.cavium.key.parameter.CaviumECGenParameterSpec;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Asymmetric key generation examples.
 */
public class AsymmetricKeys {
    /**
     * Generate an EC key pair using the given curve.
     * The label passed will be appended with ":public" and ":private" for the respective keys.
     * Supported curves are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     * Curve names are
     *     CaviumECGenParameterSpec.PRIME256V1 = "prime256v1";
     *     CaviumECGenParameterSpec.PRIME256 = "secp256r1";
     *     CaviumECGenParameterSpec.PRIME384 = "secp384r1";
     * @param curveName
     * @param label
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public KeyPair generateECKeyPair(String curveName, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = false;

        return generateECKeyPairWithParams(curveName, label, isExtractable, isPersistent);
    }

    public KeyPair generateECKeyPairWithParams(String curveName, String label, boolean isExtractable, boolean isPersistent)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "Cavium");
        keyPairGen.initialize(
                new CaviumECGenParameterSpec(
                        curveName,
                        label + ":public",
                        label + ":private",
                        isExtractable,
                        isPersistent));

        return keyPairGen.generateKeyPair();
    }

    /**
     * Generate an RSA key pair.
     * The label passed will be appended with ":public" and ":private" for the respective keys.
     * @param keySizeInBits
     * @param label
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public KeyPair generateRSAKeyPair(int keySizeInBits, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = false;

        return generateRSAKeyPairWithParams(keySizeInBits, label, isExtractable, isPersistent);
    }

    public KeyPair generateRSAKeyPairWithParams(int keySizeInBits, String label, boolean isExtractable, boolean isPersistent)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("rsa", "Cavium");;
        CaviumRSAKeyGenParameterSpec spec = new CaviumRSAKeyGenParameterSpec(keySizeInBits, new BigInteger("65537"), label + ":public", label + ":private", isExtractable, isPersistent);

        keyPairGen.initialize(spec);

        return keyPairGen.generateKeyPair();
    }
}
