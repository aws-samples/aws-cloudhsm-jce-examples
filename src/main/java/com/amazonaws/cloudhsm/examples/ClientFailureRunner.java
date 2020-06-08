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
import com.cavium.cfm2.LoginManager;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.concurrent.TimeUnit;

/**
 * This sample demonstrates how to recover from a client daemon failure.
 * A session key is generated and used to sign and verify data. You can
 * test the failure mode by restarting the client.
 *
 *    service cloudhsm-client restart
 *
 * You will see this sample detect a client failure, and attempt to recover.
 */
public final class ClientFailureRunner {
    public static void main(final String[] args) {
        String sampleMessage = "This is a sample message.";
        String signingAlgorithm = "SHA512withRSA/PSS";

        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // We assume the service runs forever.
        int retries = 5;
        boolean serviceIsRunning = true;
        while (serviceIsRunning) {
            KeyPair kp = null;

            // Each iteration of the service loop has to authenticate to the cluster
            // and generate a session keypair.
            try {
                loginUsingJavaProperties();
                kp = getSessionKeyPair();
            } catch (Exception ex) {
                if (isPeerDisconnected(ex)) {
                    // If the client disconnected, backoff and try again.
                    System.out.println("Client disconnected");
                    if (retries-- > 0) {
                        System.out.println("Backing off");
                        try {
                            TimeUnit.SECONDS.sleep(1);
                        } catch (Exception e) {
                        }
                        continue;
                    }

                    throw new RuntimeException("Could not connect after 5 retries");
                } else if (CFM2Exception.isAuthenticationFailure(ex)) {
                    // During client startup there are conditions where authentication channels
                    // are not yet active. This can cause a temporary authentication failure.
                    System.out.println("Authentication failure during client startup");
                    continue;
                } else {
                    System.out.println("Unknown exception thrown");
                    throw new RuntimeException(ex);
                }
            }

            // Reset the counter now that a successful connection has occurred.
            retries = 5;

            // Sign / verify operations are performed while the session is active.
            // If the session dies, all information associated with the session
            // is lost. This means we need to break out of the loop in order to
            // reauthenticate and generate a new signing keypair.
            boolean sessionIsActive = true;
            while (sessionIsActive) {
                try {
                    byte[] signature = signMessage(sampleMessage, signingAlgorithm, kp.getPrivate());

                    boolean isVerificationSuccessful = verifySign(sampleMessage,
                            signingAlgorithm,
                            kp.getPublic(),
                            signature);
                    System.out.printf(".");
                } catch (Exception ex) {
                    if (isPeerDisconnected(ex)) {
                        System.out.println("Detected client disconnect");
                        sessionIsActive = false;
                    } else {
                        System.out.println("Exception while sign/verfying");
                        throw new RuntimeException(ex);
                    }
                }
            }
        }
    }

    /**
     * signMessage will sign the message using the passed key and return the signature.
     * @param message
     * @param signingAlgorithm
     * @param privateKey
     * @return byte[] Signature
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     */
    public static byte[] signMessage(
            final String message,
            final String signingAlgorithm,
            final PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException, UnsupportedEncodingException {
        Signature sig = Signature.getInstance(signingAlgorithm, "Cavium");
        sig.initSign(privateKey);
        sig.update(message.getBytes("UTF-8"));
        return sig.sign();
    }

    /**
     * verifySign will verify the passed signature using the passed message and key.
     * @param message
     * @param signingAlgorithm
     * @param publicKey
     * @param signature
     * @return boolean indicating success or failure
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     */
    public static boolean verifySign(
            final String message,
            final String signingAlgorithm,
            final PublicKey publicKey,
            final byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException, UnsupportedEncodingException {
        Signature sig = Signature.getInstance(signingAlgorithm, "Cavium");
        sig.initVerify(publicKey);
        sig.update(message.getBytes("UTF-8"));

        return sig.verify(signature);
    }

    /**
     * Login to the cluster using Java system properties.
     * @throws CFM2Exception
     */
    public static void loginUsingJavaProperties() throws CFM2Exception {
        System.setProperty("HSM_PARTITION", "PARTITION_1");
        System.setProperty("HSM_USER", "crypto_user");
        System.setProperty("HSM_PASSWORD", "1234567");

        LoginManager lm = LoginManager.getInstance();
        lm.login();
    }

    /**
     * Return a 2048 bit key pair attached to the current session.
     * Since this is a session key, it will disappear if there is a
     * network failure which terminates the connection to the HSM.
     * @return
     * @throws CFM2Exception
     */
    public static KeyPair getSessionKeyPair() {
        try {
            KeyPairGenerator keyPairGen;
            keyPairGen = KeyPairGenerator.getInstance("rsa", "Cavium");

            // Create a session keypair
            keyPairGen.initialize(new CaviumRSAKeyGenParameterSpec(2048, new BigInteger("65537"), "ClientTestPublic", "ClientTestPrivate", false, false));
            System.out.println("Generated a new session key pair");
            return keyPairGen.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * isPeerDisconnected will return a boolean indicating whether a network error occurred.
     * The Throwable is unwrapped until a CFM2Exception is found.
     * @param t
     * @return
     */
    private static boolean isPeerDisconnected(Throwable t) {
        // This condition is the canonical way to check for client failures.
        if (CFM2Exception.isClientDisconnectError(t)) {
            return true;
        }

        // There are cluster errors which aren't handled above, so
        // unwrap the exception to look for specific error codes.
        while (null != t && !(t instanceof CFM2Exception)) {
            t = t.getCause();
        }

        // Check for a cluster error, which doesn't require a reconnect.
        // In this case, this application will backoff until the cluster
        // is reachable again.
        if (null != t) {
            int RET_CLUSTER_ERROR = 0x30000088;
            return ((CFM2Exception) t).getStatus() == RET_CLUSTER_ERROR;
        }

        return false;
    }
}
