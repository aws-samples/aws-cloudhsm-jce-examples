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
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Mac;

/**
 * Demonstrate basic HMAC operation.
 */
public class HMACOperationsRunner {

    /**
     * Digest a message using the passed algorithm.
     * Supported digest types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param key
     * @param algorithm
     * @param provider
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] digest(byte[] message, Key key, String algorithm, String provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Mac mac = Mac.getInstance(algorithm, provider);
        mac.init(key);
        mac.update(message);
        return mac.doFinal();
    }

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String plainText = "This is a sample Plain Text Message!";

        Key key = SymmetricKeys.generateHmacKey("HmacTest");
        String algorithm = "HmacSHA1";

        byte[] cloudHsmDigest = digest(plainText.getBytes("UTF-8"), key, algorithm, CloudHsmProvider.PROVIDER_NAME);
        System.out.println("CloudHSM HMAC= " + Base64.getEncoder().encodeToString(cloudHsmDigest));
    }
}
