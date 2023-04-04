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

import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Symmetric key generation examples. */
public class SymmetricKeys {
    /**
     * Generate an AES key with a specific label and keysize.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel Label to associate with the key.
     */
    public static Key generateAESKey(int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return generateAESKey(keySizeInBits, keyLabel, new KeyAttributesMap());
    }

    /**
     * Generate an AES key with a specific label and keysize.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel Label to associate with the key.
     */
    public static Key generateAESKey(
            int keySizeInBits, String keyLabel, KeyAttributesMap aesSpecKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        // Create an Aes keygen Algorithm parameter spec using KeyAttributesMap
        final KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.putAll(aesSpecKeyAttributes);
        aesSpec.put(KeyAttribute.LABEL, keyLabel);
        aesSpec.put(KeyAttribute.SIZE, keySizeInBits);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        keyGen.init(aesSpec);
        SecretKey aesKey = keyGen.generateKey();

        return aesKey;
    }

    /**
     * Generate a Hmac key with a specific label.
     *
     * @param keyLabel Label to associate with the key.
     */
    public static Key generateHmacKey(String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {

        // Create an Hmac keygen Algorithm parameter spec using KeyAttributesMap
        KeyAttributesMap hmacSpec = new KeyAttributesMap();
        hmacSpec.put(KeyAttribute.LABEL, keyLabel);
        hmacSpec.put(KeyAttribute.SIZE, 192);

        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1", CloudHsmProvider.PROVIDER_NAME);
        keyGen.init(hmacSpec);
        SecretKey hmacKey = keyGen.generateKey();

        return hmacKey;
    }

    /**
     * Generate a DES key with a specific label.
     *
     * @param keyLabel
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static Key generateDESKey(String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    NoSuchProviderException, AddAttributeException {
        return doGenerateDESKey(keyLabel, CloudHsmProvider.PROVIDER_NAME);
    }

    /**
     * Generate a DES key with a specific label and given provider.
     *
     * @param keyLabel
     * @param providerName provider to be used
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static Key doGenerateDESKey(String keyLabel, String providerName)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            AddAttributeException{
        // Create a Des3 keygen Algorithm parameter spec using KeyAttributesMap
        KeyAttributesMap desSpec = new KeyAttributesMap();
        desSpec.put(KeyAttribute.LABEL, keyLabel);

        KeyGenerator keyGen = KeyGenerator.getInstance("DESede", providerName);
        keyGen.init(desSpec);
        SecretKey des3Key = keyGen.generateKey();
        return des3Key;
    }
}
