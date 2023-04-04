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

import com.amazonaws.cloudhsm.jce.provider.CloudHsmCluster;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmLoggingConfig;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProviderConfig;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmServer;
import com.amazonaws.cloudhsm.jce.provider.OptionalParameters;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.text.MessageFormat;
import java.util.Base64;
import java.util.Random;


/**
 * Demonstrate basic Multi User Multi Cluster operation while connecting to 2 different clusters.
 * <p>
 * Usage: The info of the 2 clusters for multi user multi cluster use cases should be provided as command
 * line arguments as below.
 * <p>
 * <cluster-1-hsm-ca-cert> <cluster-1-hsm-ip> <cluster-1-user-pin> <cluster-2-hsm-ca-cert> <cluster-2-hsm-ip> <cluster-2-user-pin>
 * > hsm ca cert file path is the absolute path. e.g. /opt/cloudhsm/etc/customerCA.crt, /opt/cloudhsm/etc/customerCA2.crt
 * > hsm ip is the ip address of the HSM in a cluster. e.g. 1.2.3.4
 * > user pin will be of the format as <user_name>:<password>. e.g. cu:password.
 */
public class MultiUserMultiClusterRunner {
    private static final String CLUSTER_DESEDE_PROVIDER_NAME = "cluster_desede_provider";
    private static final String CLUSTER_RSA_PROVIDER_NAME = "cluster_rsa_provider";
    private static String helpString = "MultiUserMultiClusterRunner\n" +
            "This sample demonstrates how to connect to 2 clusters and perform operation.\n\n" +
            "Options\n" +
            "\t--help   Display this message.\n" +
            "\t--cluster-1-hsm-ca-cert <hsm filepath>  Absolute path of hsm ca cert file for cluster 1. e.g. /opt/cloudhsm/etc/customerCA.crt\n" +
            "\t--cluster-1-hsm-ip <hsm ip>  HSM IP for a HSM in cluster 1.\n" +
            "\t--cluster-1-user-pin <user login pin>  login pin for cluster 1. e.g. as <user_name>:<password> like cu1:password1.\n" +
            "\t--cluster-2-hsm-ca-cert <hsm filepath>  Absolute path of hsm ca cert file for cluster 2. e.g. /opt/cloudhsm/etc/customerCA2.crt\n" +
            "\t--cluster-2-hsm-ip <hsm ip>  HSM IP for a HSM in cluster 2.\n" +
            "\t--cluster-2-user-pin <user login pin>  login pin cluster 2. e.g. as <user_name>:<password> like cu2:password2.\n\n";

    public static void main(String[] args) throws Exception {
        String hsmFilePath1 = null;
        String hsmIp1 = null;
        String userLoginPin1 = null;
        String hsmFilePath2 = null;
        String hsmIp2 = null;
        String userLoginPin2 = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--cluster-1-hsm-ca-cert":
                    hsmFilePath1 = args[++i];
                    break;
                case "--cluster-1-hsm-ip":
                    hsmIp1 = args[++i];
                    break;
                case "--cluster-1-user-pin":
                    userLoginPin1 = args[++i];
                    break;
                case "--cluster-2-hsm-ca-cert":
                    hsmFilePath2 = args[++i];
                    break;
                case "--cluster-2-hsm-ip":
                    hsmIp2 = args[++i];
                    break;
                case "--cluster-2-user-pin":
                    userLoginPin2 = args[++i];
                    break;
                case "--help":
                    help();
                    return;
            }
        }

        if (isInvalid(hsmFilePath1) || isInvalid(hsmIp1) || isInvalid(userLoginPin1) || isInvalid(hsmFilePath2)
                || isInvalid(hsmIp2) || isInvalid(userLoginPin2)) {
            help();
            return;
        }

        if (System.getenv().containsKey("HSM_USER") || System.getenv().containsKey("HSM_PASSWORD") ) {
            throw new IllegalStateException("The env variables HSM_USER and HSM_PASSWORD need to be unset before running the sample");
        }

        try {
            CloudHsmProvider desedeClusterProvider = null;
            if (Security.getProvider(CLUSTER_DESEDE_PROVIDER_NAME) == null) {
                desedeClusterProvider = createProvider(CLUSTER_DESEDE_PROVIDER_NAME, hsmFilePath1, hsmIp1);
                Security.addProvider(desedeClusterProvider);
                System.out.println(MessageFormat.format("Created and added CloudHsmProvider with unique ID: {0} to the JavaSecurity configuration", CLUSTER_DESEDE_PROVIDER_NAME));

                String[] userNameAndPassword = userLoginPin1.split(":");
                String user1 = userNameAndPassword[0];
                String password1 = userNameAndPassword[1];
                LoginRunner.loginWithPinOnGivenProvider(user1, password1, CLUSTER_DESEDE_PROVIDER_NAME);
            }

            CloudHsmProvider rsaClusterProvider = null;
            if (Security.getProvider(CLUSTER_RSA_PROVIDER_NAME) == null) {
                rsaClusterProvider = createProvider(CLUSTER_RSA_PROVIDER_NAME, hsmFilePath2, hsmIp2);
                Security.addProvider(rsaClusterProvider);
                System.out.println(MessageFormat.format(" Created and added CloudHsmProvider with unique ID: {0} to the JavaSecurity configuration", CLUSTER_RSA_PROVIDER_NAME));

                String[] userNameAndPassword = userLoginPin2.split(":");
                String user2 = userNameAndPassword[0];
                String password2 = userNameAndPassword[1];
                LoginRunner.loginWithPinOnGivenProvider(user2, password2, CLUSTER_RSA_PROVIDER_NAME);
            }

            System.out.println("\nStarted executing DESede operations on provider " + CLUSTER_DESEDE_PROVIDER_NAME);
            performDESedeEncryptAndDecrypt();
            System.out.println("Finished executing operations on provider " + CLUSTER_DESEDE_PROVIDER_NAME + "\n");
            LoginRunner.logout(desedeClusterProvider);

            System.out.println("Started executing RSA operations on provider " + CLUSTER_RSA_PROVIDER_NAME);
            performRSAEncryptAndDecrypt();
            performRSASignAndVerify();
            System.out.println("Finished executing operations on provider " + CLUSTER_RSA_PROVIDER_NAME);
            LoginRunner.logout(rsaClusterProvider);
        } catch (IOException ex) {
            System.out.println(ex);
        }
    }

    private static boolean isInvalid(String requiredParameter) {
        return requiredParameter == null || requiredParameter.isEmpty();
    }

    private static void help() {
        System.out.println(helpString);
    }

    public static CloudHsmProvider createProvider(String clusterUniqueId,
                                                  String caFilePath,
                                                  String hostIp)
            throws Exception {
        final CloudHsmServer server = CloudHsmServer.builder()
                .withHostIP(hostIp)
                .build();

        final CloudHsmCluster cluster = CloudHsmCluster.builder()
                .withClusterUniqueIdentifier(clusterUniqueId)
                .withHsmCAFilePath(caFilePath)
                .withOptions(OptionalParameters.VALIDATE_KEY_AT_INIT, false)
                .withServer(server)
                .build();

        final CloudHsmLoggingConfig loggingConfig = CloudHsmLoggingConfig.builder()
                .withLogFile("/opt/cloudhsm/run/cloudhsm-jce.log")
                .withLogInterval("daily")
                .withLogType("file")
                .withLogLevel("info")
                .build();

        final CloudHsmProviderConfig testConfig = CloudHsmProviderConfig.builder()
                .withCluster(cluster)
                .withCloudHsmLogging(loggingConfig)
                .build();
        return new CloudHsmProvider(testConfig);
    }

    private static void performRSAEncryptAndDecrypt() throws Exception {
        String plainText = "This is a sample Plain Text Message!";
        String transformation = "RSA/ECB/OAEPPadding";
        String providerName = CLUSTER_RSA_PROVIDER_NAME;

        KeyPair kp = AsymmetricKeys.generateRSAKeyPair(2048, "rsa encrypt decrypt test", providerName);

        // RSA Encrypt
        System.out.println("Performing RSA Encryption Operation");
        Cipher encCipher = Cipher.getInstance(transformation, providerName);
        encCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] cipherText = encCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted plaintext = " + Base64.getEncoder().encodeToString(cipherText));

        // RSA Decrypt
        Cipher decCipher = Cipher.getInstance(transformation, providerName);
        decCipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decryptedText = decCipher.doFinal(cipherText);
        String decryptedPlainText = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Decrypted text = " + decryptedPlainText);
        assert (java.util.Arrays.equals(plainText.getBytes(StandardCharsets.UTF_8), decryptedText));
    }

    private static void performRSASignAndVerify() throws Exception {
        String plainText = "This is a sample Plain Text Message!";
        String signingAlgorithm = "SHA512withRSA";
        String providerName = CLUSTER_RSA_PROVIDER_NAME;

        KeyPair kp = AsymmetricKeys.generateRSAKeyPair(2048, "rsa sign verify test", providerName);

        // RSA Sign
        Signature sig = Signature.getInstance(signingAlgorithm, providerName);
        sig.initSign(kp.getPrivate());
        sig.update(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        System.out.println("RSA signature = " + Base64.getEncoder().encodeToString(signature));

        // RSA Verify
        sig.initVerify(kp.getPublic());
        sig.update(plainText.getBytes(StandardCharsets.UTF_8));
        if (sig.verify(signature)) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature is invalid!");
        }
    }

    private static void performDESedeEncryptAndDecrypt() throws Exception {
        String providerName = CLUSTER_DESEDE_PROVIDER_NAME;
        // Generate a new DES Key to use for encryption.
        Key key = SymmetricKeys.doGenerateDESKey("DesEcbTest", providerName);
        System.out.println(MessageFormat.format("Generated the DES key to use for encryption on cluster {0}", providerName));

        // Generate some random data to encrypt
        byte[] plainText = new byte[1024];
        Random r = new Random();
        r.nextBytes(plainText);

        // Encrypt the plaintext
        Cipher encCipher = Cipher.getInstance("DESede/ECB/NoPadding", providerName);
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = encCipher.doFinal(plainText);
        System.out.println(MessageFormat.format("Encrypted using the generated DES key on cluster {0}", providerName));

        // Decrypt the ciphertext and verify with the original plaintext.
        Cipher decCipher = Cipher.getInstance("DESede/ECB/NoPadding", providerName);
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedText = decCipher.doFinal(cipherText);
        assert (java.util.Arrays.equals(plainText, decryptedText));
        System.out.println(MessageFormat.format("Decrypted successfully using the generated DES key on cluster {0}", providerName));
    }
}
