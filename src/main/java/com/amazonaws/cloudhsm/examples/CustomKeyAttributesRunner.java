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

import com.amazonaws.cloudhsm.CloudHsmKeyAttributes;
import com.amazonaws.cloudhsm.CloudHsmKeyAttributesMap;
import com.amazonaws.cloudhsm.CloudHsmKeyPairAttributesMap;
import com.cavium.cfm2.ImportKey;
import com.cavium.crypto.parameter.CaviumUnwrapParameterSpec;
import com.cavium.key.CaviumKey;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;
import com.cavium.key.parameter.CaviumECGenParameterSpec;
import com.cavium.key.parameter.CaviumGenericSecretKeyGenParameterSpec;
import com.cavium.provider.CaviumProvider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * This sample demonstrates how one can perform the following operations while leveraging the
 * Custom Key Attributes feature:  Key Unwrapping, Key Generation, and Key Import.
 */
public class CustomKeyAttributesRunner {

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new CaviumProvider());
        } catch (IOException ex) {
            System.err.println(ex);
            return;
        }

        unwrapWithAesKey();
        generateEcKeyPair();
        importHmacKey();
    }

    /**
     * A convenience method for generating an AES key.
     *
     * @param keySizeInBits The key's size (in bits).
     * @param label The key's label (aka CKA_LABEL).
     * @param extractable Whether the key will be extractable (aka CKA_EXTRACTABLE).
     * @param persistent Whether the key will be stored in the HSM (aka CKA_TOKEN).
     * @return A newly-created AES key using the provided parameters.
     * @throws Exception If any of these are incorrect: algorithm, provider, algorithm parameters,
     * etc.
     */
    private static SecretKey generateKeyAes(
            final int keySizeInBits,
            final String label,
            final boolean extractable,
            final boolean persistent)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {

        // Create and configure a key generator for AES keys using the Cavium provider.
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");
        keyGen.init(
                new CaviumAESKeyGenParameterSpec(
                        keySizeInBits,
                        label,
                        extractable,
                        persistent
                )
        );

        // Generate and return a key object.
        return keyGen.generateKey();
    }

    /**
     * A convenience method for verifying that a key contains a specific key attribute and value.
     *
     * @param key The key object whose key attributes and values will be examined.
     * @param keyAttr The key attribute for which we'll search in the key.
     * @param expectedValue The value that is expected to be assigned to <code>keyAttr</code>.
     */
    private static void verifyKeyHasKeyAttrAndValue(
            final CaviumKey key,
            final CloudHsmKeyAttributes keyAttr,
            final Object expectedValue) {

        // Ensure that the provided key attribute is present in the key.
        assert key.getCloudHsmKeyAttributesMap().containsKey(keyAttr)
                : String.format("Key attribute %s not present on key.", keyAttr);

        // Ensure that the key attribute has been assigned the provided value.
        assert key.getCloudHsmKeyAttributesMap().get(keyAttr).equals(expectedValue)
                : String.format("Key attribute %s expected to have value '%s' but found '%s'.",
                keyAttr, expectedValue, key.getCloudHsmKeyAttributesMap().get(keyAttr));
    }

    /*
     * Demonstrate the unwrapping of a wrapped key while using Custom Key Attributes.
     */
    private static void unwrapWithAesKey() throws Exception {
        // Generate some plaintext for our operation.
        final byte[] plainText = new byte[512];
        final Random r = new Random();
        r.nextBytes(plainText);

        // Generate an AES payload key; this will be wrapped into the HSM in a following step.
        final int payloadKeyAesKeySizeInBits = 256;
        final String payloadKeyAesLabel = "AES Payload Key";
        final boolean payloadKeyAesExtractable = true;
        final boolean payloadKeyAesPersistent = true;

        final CaviumKey payloadKeyAes = (CaviumKey) generateKeyAes(
                payloadKeyAesKeySizeInBits,
                payloadKeyAesLabel,
                payloadKeyAesExtractable,
                payloadKeyAesPersistent
        );

        // Demonstrate that the key contains the attributes we've set above.
        System.out.format("The payload key's attributes: %s%n", payloadKeyAes.getCloudHsmKeyAttributesMap());
        verifyKeyHasKeyAttrAndValue(payloadKeyAes, CloudHsmKeyAttributes.CKA_LABEL, payloadKeyAesLabel);
        verifyKeyHasKeyAttrAndValue(payloadKeyAes, CloudHsmKeyAttributes.CKA_EXTRACTABLE, payloadKeyAesExtractable);
        verifyKeyHasKeyAttrAndValue(payloadKeyAes, CloudHsmKeyAttributes.CKA_TOKEN, payloadKeyAesPersistent);

        // Encrypt the plaintext using the payload key.
        final Cipher encCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "Cavium");
        encCipher.init(Cipher.ENCRYPT_MODE, payloadKeyAes);
        final byte[] cipherText = encCipher.doFinal(plainText);

        // Generate a key to perform the wrapping and unwrapping operations.
        // It must be imported into the HSM so that the payload can be (un)wrapped.
        final int wrapUnwrapKeyAesKeySizeInBits = 256;
        final String wrapUnwrapKeyAesLabel = "AES Wrap/Unwrap Key";
        final boolean wrapUnwrapKeyAesExtractable = true;
        final boolean wrapUnwrapKeyAesPersistent = true; // must be TRUE; the key must be imported into the HSM to permit (un)wrapping

        final CaviumKey wrapUnwrapKeyAes = (CaviumKey) generateKeyAes(
                wrapUnwrapKeyAesKeySizeInBits,
                wrapUnwrapKeyAesLabel,
                wrapUnwrapKeyAesExtractable,
                wrapUnwrapKeyAesPersistent
        );

        // Demonstrate that the key contains the attributes we've set above.
        System.out.format("The wrap/unwrap key's attributes: %s%n", wrapUnwrapKeyAes.getCloudHsmKeyAttributesMap());
        verifyKeyHasKeyAttrAndValue(wrapUnwrapKeyAes, CloudHsmKeyAttributes.CKA_LABEL, wrapUnwrapKeyAesLabel);
        verifyKeyHasKeyAttrAndValue(wrapUnwrapKeyAes, CloudHsmKeyAttributes.CKA_EXTRACTABLE, wrapUnwrapKeyAesExtractable);
        verifyKeyHasKeyAttrAndValue(wrapUnwrapKeyAes, CloudHsmKeyAttributes.CKA_TOKEN, wrapUnwrapKeyAesPersistent);

        // Wrap the payload key using the wrapping key.
        final Cipher wrapCipher = Cipher.getInstance("AESWrap", "Cavium");
        wrapCipher.init(Cipher.WRAP_MODE, wrapUnwrapKeyAes);
        final byte[] wrappedBytes = wrapCipher.wrap(payloadKeyAes);

        // Unwrap the wrapped payload key (raw bytes) using the unwrapping key.
        // Note how an instance of CloudHsmKeyAttributesMap is provided as a parameter to the
        // CaviumUnwrapParameterSpec constructor.
        final String unwrappedKeyLabel = "Unwrapped Key";
        final CloudHsmKeyAttributesMap unwrapKeyAttrsMap = new CloudHsmKeyAttributesMap.Builder()
                .put(CloudHsmKeyAttributes.CKA_LABEL, unwrappedKeyLabel)
                .build();
        final CaviumUnwrapParameterSpec unwrapSpec = new CaviumUnwrapParameterSpec(
                null,
                unwrapKeyAttrsMap
        );
        final Cipher unwrapCipher = Cipher.getInstance("AESWrap", "Cavium");
        unwrapCipher.init(Cipher.UNWRAP_MODE, wrapUnwrapKeyAes, unwrapSpec);
        final CaviumKey unwrappedKey = (CaviumKey) unwrapCipher
                .unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Demonstrate that the unwrapped key contains the attributes we've set above.
        System.out.format("The unwrapped key's attributes: %s%n", unwrappedKey.getCloudHsmKeyAttributesMap());
        verifyKeyHasKeyAttrAndValue(unwrappedKey, CloudHsmKeyAttributes.CKA_LABEL, unwrappedKeyLabel);
        // Not only must CKA_DECRYPT be enabled for key unwrapping, but it is one of several key
        // attributes that will be enabled if no value is provided by the caller.
        // See https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-attributes.html#java-attributes
        // for additional details.
        verifyKeyHasKeyAttrAndValue(unwrappedKey, CloudHsmKeyAttributes.CKA_DECRYPT, true);

        // Decrypt the ciphertext using the unwrapped key; it should match the plaintext.
        final Cipher decCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "Cavium");
        final IvParameterSpec ivSpec = new IvParameterSpec(encCipher.getIV());
        decCipher.init(Cipher.DECRYPT_MODE, unwrappedKey, ivSpec);
        final byte[] decryptedBytes = decCipher.doFinal(cipherText);

        // Verify that the plaintext and decrypted ciphertext are identical.
        assert Arrays.equals(plainText, decryptedBytes) : "Plaintext and decrypted ciphertext do not match.";
    }

    /*
     * Demonstrate the generation of an EC key pair while using Custom Key Attributes.
     */
    private static void generateEcKeyPair() throws Exception {
        final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "Cavium");

        // Demonstrate the construction of a CloudHsmKeyAttributesMap for the public key by first
        // instantiating the class and adding key-value pairs, much like would be done via
        // Map objects.
        final String ecPublicKeyLabel = "EC Public Key";
        final boolean ecPublicKeyExtractable = true;
        final boolean ecPublicKeyPersistent = false;

        final CloudHsmKeyAttributesMap publicKeyAttrsMap = new CloudHsmKeyAttributesMap();
        publicKeyAttrsMap.put(CloudHsmKeyAttributes.CKA_LABEL, ecPublicKeyLabel);
        publicKeyAttrsMap.put(CloudHsmKeyAttributes.CKA_EXTRACTABLE, ecPublicKeyExtractable);
        publicKeyAttrsMap.put(CloudHsmKeyAttributes.CKA_TOKEN, ecPublicKeyPersistent);

        // Demonstrate the construction of a CloudHsmKeyAttributesMap for the private key using
        // the Builder pattern.  Note how method chaining is supported.
        final String ecPrivateKeyLabel = "EC Private Key";
        final boolean ecPrivateKeyExtractable = true;
        final boolean ecPrivateKeyPersistent = false;

        final CloudHsmKeyAttributesMap privateKeyAttrsMap = new CloudHsmKeyAttributesMap.Builder()
                .put(CloudHsmKeyAttributes.CKA_LABEL, ecPrivateKeyLabel)
                .put(CloudHsmKeyAttributes.CKA_EXTRACTABLE, ecPrivateKeyExtractable)
                .put(CloudHsmKeyAttributes.CKA_TOKEN, ecPrivateKeyPersistent)
                .build();

        // Instantiate CaviumECGenParameterSpec for use during generation of the EC key pair.
        // Note how the Builder pattern is used to construct a CloudHsmKeyPairAttributesMap from
        // the previous public and private key attributes maps.
        final CaviumECGenParameterSpec spec = new CaviumECGenParameterSpec(
                "prime256v1",
                new CloudHsmKeyPairAttributesMap.Builder()
                        .withPublic(publicKeyAttrsMap)
                        .withPrivate(privateKeyAttrsMap)
                        .build()
        );
        keyPairGen.initialize(spec);
        final KeyPair keyPair = keyPairGen.generateKeyPair();

        // Demonstrate that the public key contains the attributes we've set above.
        final CaviumKey ecPublicKey = (CaviumKey) keyPair.getPublic();
        System.out.format("The EC public key's attributes: %s%n", ecPublicKey.getCloudHsmKeyAttributesMap());
        verifyKeyHasKeyAttrAndValue(ecPublicKey, CloudHsmKeyAttributes.CKA_LABEL, ecPublicKeyLabel);
        verifyKeyHasKeyAttrAndValue(ecPublicKey, CloudHsmKeyAttributes.CKA_EXTRACTABLE, ecPublicKeyExtractable);
        verifyKeyHasKeyAttrAndValue(ecPublicKey, CloudHsmKeyAttributes.CKA_TOKEN, ecPublicKeyPersistent);

        // Demonstrate that the private key contains the attributes we've set above.
        final CaviumKey ecPrivateKey = (CaviumKey) keyPair.getPrivate();
        System.out.format("The EC public key's attributes: %s%n", ecPrivateKey.getCloudHsmKeyAttributesMap());
        verifyKeyHasKeyAttrAndValue(ecPrivateKey, CloudHsmKeyAttributes.CKA_LABEL, ecPrivateKeyLabel);
        verifyKeyHasKeyAttrAndValue(ecPrivateKey, CloudHsmKeyAttributes.CKA_EXTRACTABLE, ecPrivateKeyExtractable);
        verifyKeyHasKeyAttrAndValue(ecPrivateKey, CloudHsmKeyAttributes.CKA_TOKEN, ecPrivateKeyPersistent);
    }

    /*
     * Demonstrate the import of an externally-generated Generic Secret key while using Custom Key
     * Attributes.
     */
    private static void importHmacKey() throws Exception {

        final int hmacKeySize = 512;

        // Generate a key using the SunJCE provider.
        final KeyGenerator keyGen = KeyGenerator.getInstance("HMacSHA512", "SunJCE");
        keyGen.init(hmacKeySize);
        final SecretKey sk = keyGen.generateKey();

        // Import the key into the HSM.
        final String genericSecretKeyLabel = "Generic Secret Key";
        final boolean genericSecretKeyExtractable = true;
        final boolean genericSecretKeyPersistent = false;

        // Instantiate CaviumGenericSecretKeyGenParameterSpec for use during import of the Generic
        // Secret key.
        final CloudHsmKeyAttributesMap keyAttrsMap = new CloudHsmKeyAttributesMap.Builder()
                .put(CloudHsmKeyAttributes.CKA_LABEL, genericSecretKeyLabel)
                .put(CloudHsmKeyAttributes.CKA_EXTRACTABLE, genericSecretKeyExtractable)
                .put(CloudHsmKeyAttributes.CKA_TOKEN, genericSecretKeyPersistent)
                .build();
        final CaviumGenericSecretKeyGenParameterSpec specCavium = new CaviumGenericSecretKeyGenParameterSpec(
                hmacKeySize,
                keyAttrsMap
        );
        final CaviumKey genericSecretKey = (CaviumKey) ImportKey.importKey(sk, specCavium);

        // Demonstrate that the key contains the attributes we've set above.
        System.out.format("The key's attributes: %s%n", genericSecretKey.getCloudHsmKeyAttributesMap());
        verifyKeyHasKeyAttrAndValue(genericSecretKey, CloudHsmKeyAttributes.CKA_LABEL, genericSecretKeyLabel);
        verifyKeyHasKeyAttrAndValue(genericSecretKey, CloudHsmKeyAttributes.CKA_EXTRACTABLE, genericSecretKeyExtractable);
        verifyKeyHasKeyAttrAndValue(genericSecretKey, CloudHsmKeyAttributes.CKA_TOKEN, genericSecretKeyPersistent);
    }
}
