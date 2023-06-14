/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.cloudhsm.jce.provider.AesCmacKdfFixedInputData;
import com.amazonaws.cloudhsm.jce.provider.AesCmacKdfParameterSpec;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Security;
import java.text.MessageFormat;
import java.util.UUID;

/**
 * The sample code demonstrates the basic AES CMAC KDF operation on AWS CloudHSM. The operation has been defined by
 * the publicly available NIST SP 800-108 specification.
 *
 * The AES CMAC KDF operation is used to derive either of the 3 keys DESede, AES or GenericSecret using an AES
 * key as the base key.
 *
 * The SecretKeyFactory is used to get the instance of the corresponding derivation key algorithm
 * (DESede, AES or GenericSecret) for the provider AWS CloudHSM. The base key however which is used to derive
 * either of the Keys should be the AES key always.
 *
 * The sample code below is showing the derivation of the DESede key using the base AES key however the same example
 * can be referenced to derive other Keys as well.
 */
public class AesCmacKdfOperationsRunner {
    /**
     * Encoded fixed input data as defined by the corresponding NIST SP 800-108 specification is an array of bytes
     * which consists of multiple fields. The fields described in the specification are Label, Context, Length
     * of the Derived Key, and all-zero octet, which are defined as below.
     *
     * <p>Label is a string that identifies the purpose for the derived key.
     *
     * <p>Context is a string represented as a byte array containing the information related to the derived key.
     * It may include the identities of the parties who are deriving and/or using the derived key and, optionally,
     * a nonce known by the parties who derive the keys.
     *
     * <p>[L] Specifies the requested length (in bits) of the derived key.
     *
     * <p>An all-zero octet 0x00. It is an optional data field that is used to indicate a separation of different
     * variable-length data fields as above.
     */

    /**
     * The fixed input data is created by concatenating the 4 fields above but there is no fixed ordering. The ordering
     * of the fields Label, Context and Length of the Derived Key can be changed but the concatenation should be done
     * in such a way that the concatenation should produce either 1 array or 2 arrays.
     * First array is called as input data prefix and second array is called input data suffix.
     *
     * If all the fields are concatenated together, the concatenated array can either be considered as prefix array with
     * suffix array as null or suffix array with prefix array as null.
     * If the fields are concatenated to create 2 arrays, the first is passed as a prefix array and the second as a
     * suffix array.
     *
     * The default ordering for concatenation of the fields is (Label || 0x00 || Context || [L]) but fields may also
     * be ordered a few other ways:
     * (Label || 0x00), ([L] || Context)
     * (Label || 0x00), (Context || [L])
     * (Label), (0x00 || Context || [L]) etc.
     */
    private static final byte[] LABEL = "some_label".getBytes();
    private static final byte[] CONTEXT = "some_context".getBytes();
    private static final int DERIVED_KEY_SIZE_BITS = 192;
    private static final byte[] ENCODED_INPUT_DATA;
    /**
     * Defines the number of bits used to represent the counter value. Parameter is as per the NIST SP800-108 specification.
     */
    private static final int COUNTER_WIDTH = 8;

    static {
        // fixedInputData = label || 0x00 || context || dkLen in bits as 4 bytes big endian
        ByteBuffer buffer = ByteBuffer.allocate(LABEL.length + CONTEXT.length + 5);
        buffer.put(LABEL);
        buffer.put((byte) 0);
        buffer.put(CONTEXT);
        buffer.putInt(DERIVED_KEY_SIZE_BITS);
        ENCODED_INPUT_DATA = buffer.array();
    }

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.err.println(ex);
            System.exit(-1);
        }
        deriveKeyWithGivenSpecification();
    }

    private static void deriveKeyWithGivenSpecification() throws Exception {
        final SecretKey baseAesKey = generateBaseDerivationKey();
        final String deriveKeyLabel = "deriveKeyLabel_" + UUID.randomUUID();
        System.out.println("Deriving the specified DESEDE Key.");

        // The way to derive a key using AES CMAC KDF is by instantiating a SecretKeyFactory for the derived key
        // algorithm and passing the AesCmacKdfParameterSpec to the SecretKeyFactory instance.
        // In this case, we want to derive a DESede key, so we will instantiate a SecretKeyFactory with that algorithm
        // and pass in AesCmacKdfParameterSpec to initialize that instance.
        final String algorithm = "DESede";

        final AesCmacKdfParameterSpec specFixed = generateSpecWithFixedInputData(COUNTER_WIDTH,
                DERIVED_KEY_SIZE_BITS,
                baseAesKey,
                deriveKeyLabel);

        final SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance(algorithm, CloudHsmProvider.PROVIDER_NAME);
        final SecretKey derivedAesKeyCHSM = secretKeyFactory.generateSecret(specFixed);
        System.out.println(MessageFormat.format("Derived the specified DESEDE Key with Label: {0} successfully.", deriveKeyLabel));
    }

    /**
     * Constructs the fixed input data for AES CMAC KDF algorithm.
     * @param counterWidth Defines the number of bits used to represent the counter value. Parameter is as per the NIST SP800-108 specification.
     * @param dkmLengthInBits Defines the number of bits used to represent the derived key length. Parameter is as per the NIST SP800-108 specification.
     * @param baseAesKey The base derivation AES key which will be used to derive the required Key using the AES CMAC KDF specification. Parameter is as per the NIST SP800-108 specification.
     * @param deriveKeyLabel The label which the required key should be derived with.
     * @return The AES CMAC KDF specification to derive the key.
     * @throws Exception If JCE provider exception is thrown.
     */
    private static AesCmacKdfParameterSpec generateSpecWithFixedInputData(final int counterWidth,
                                                                          final int dkmLengthInBits,
                                                                          final SecretKey baseAesKey,
                                                                          final String deriveKeyLabel) throws Exception {
        final AesCmacKdfFixedInputData inputData =
                new AesCmacKdfFixedInputData(counterWidth, /*input data prefix*/null, /*input data suffix*/ENCODED_INPUT_DATA);
        final KeyAttributesMap keyAttributesMap = new KeyAttributesMap();
        keyAttributesMap.put(KeyAttribute.SIZE, dkmLengthInBits);
        keyAttributesMap.put(KeyAttribute.LABEL, deriveKeyLabel);
        return new AesCmacKdfParameterSpec(keyAttributesMap, inputData, baseAesKey);
    }

    private static SecretKey generateBaseDerivationKey() throws Exception {
        final String baseKeyLabel = "AesCmacTest_" + UUID.randomUUID();
        System.out.println("Generating the base AES Key");
        final KeyGenerator generator =
                KeyGenerator.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
        final KeyAttributesMap map = new KeyAttributesMap();
        map.put(KeyAttribute.LABEL, baseKeyLabel);
        map.put(KeyAttribute.SIZE, 256);
        map.put(KeyAttribute.DERIVE, true);
        generator.init(map, null);
        final SecretKey baseAesKey = generator.generateKey();
        System.out.println(MessageFormat.format("Generated the base AES Key with the Label: {0} successfully.", baseKeyLabel));
        return baseAesKey;
    }
}
