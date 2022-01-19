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
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;

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
     * Curve params list:
     *     EcParams.EC_CURVE_PRIME256;
     *     EcParams.EC_CURVE_PRIME384;
     *     EcParams.EC_CURVE_SECP256;
     * @param curveParams
     * @param label
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public KeyPair generateECKeyPair(byte[] curveParams, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            AddAttributeException {

        final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);

        // Set attributes for EC public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");
        publicKeyAttrsMap.put(KeyAttribute.EC_PARAMS, curveParams);

        // Set attributes for EC private key
        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, label + ":Private")
                .build();

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec = new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();
        keyPairGen.initialize(keyPairSpec);

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
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            AddAttributeException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);

        // Set attributes for RSA public key
        final KeyAttributesMap publicKeyAttrsMap = new KeyAttributesMap();
        publicKeyAttrsMap.put(KeyAttribute.LABEL, label + ":Public");
        publicKeyAttrsMap.put(KeyAttribute.MODULUS_BITS, keySizeInBits);
        publicKeyAttrsMap.put(KeyAttribute.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray());

        // Set attributes for RSA private key
        final KeyAttributesMap privateKeyAttrsMap = new KeyAttributesMapBuilder()
                .put(KeyAttribute.LABEL, label + ":Private")
                .build();

        // Create KeyPairAttributesMap and use that to initialize the keyPair generator
        KeyPairAttributesMap keyPairSpec = new KeyPairAttributesMapBuilder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build();

        keyPairGen.initialize(keyPairSpec);

        return keyPairGen.generateKeyPair();
    }
}
