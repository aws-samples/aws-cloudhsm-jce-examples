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
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;

import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * This sample uses RSA OAEP padding to import a wrapped AES key.
 * You can test this sample by wrapping a key from the command line using OpenSSL. You must generate a keypair locally,
 * and then convert the private key to PKCS8 format so that it can be imported into the CloudHSM:
 *
 * ```
 *    $ openssl genrsa -out rsaprivate2048.pem 2048
 *    $ openssl rsa -pubout -in rsaprivate2048.pem -out rsapublic2048.pem
 *    $ openssl pkcs8 -topk8 -inform PEM -in rsaprivate2048.pem -out rsaprivate2048_pkcs8.pem -nocrypt
 *```

 * Next, generate an AES key to wrap:
 *
 * ```
 *    $ openssl rand 32 > aes32
 * ```
 *
 * Now you are able wrap the aes32 key with the same parameters as you pass to this example.
 * The resulting file, `aes32_wrapped_oaep_${HASH}`, can be used as the input to this sample.
 *
 * ```
 *    $ export HASH=SHA256
 *    $ openssl pkeyutl -encrypt \
 *       -in aes32 -out aes32_wrapped_oaep_${HASH} \
 *       -pkeyopt rsa_padding_mode:oaep \
 *       -pkeyopt rsa_oaep_md:${HASH} \
 *       -pkeyopt rsa_mgf1_md:${HASH} \
 *       -pubin -inkey rsapublic2048.pem
 * ```
 *
 * At this point you can run this sample using the rsaprivate2048_pkcs8.pem file for --unwrapping-key and the
 * aes_wrapped_oaep_${HASH} file for the --wrapped-key
 */
public class RSAImportKey {
    private static String helpString = "RSAImportKey\n" +
            "This tool uses an RSA private key to unwrap an AES key. The AES key must have been wrapped with OAEP padding\n" +
            "\n" +
            "Options\n" +
            "\t--hash\t\t\tType of hash used to wrap [SHA1, SHA256(default)].\n" +
            "\t--key-size\t\tSize of the wrapping key in bits [2048, 4096].\n" +
            "\t--wrapped-key\t\tLocation of AES Wrapped key.\n" +
            "\t--unwrapping-key\tLocation of unwrapping key, in PKCS8 format.\n";

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new CloudHsmProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String keyFile = null;
        String hash = null;
        String transformation = null;
        String unwrappingKeyFile = null;
        Integer keySize = 0;


        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--unwrapping-key":
                    unwrappingKeyFile = args[++i];
                    System.out.println(unwrappingKeyFile);
                    break;
                case "--hash":
                    hash = args[++i];
                    break;
                case "--wrapped-key":
                    keyFile = args[++i];
                    break;
                case "--key-size":
                    keySize = Integer.valueOf(args[++i]);
                    if (0 != keySize % 8) {
                        System.out.println("Key bits must be a multiple of 8");
                        help();
                        return;
                    }
                    keySize = keySize / 8;
                    break;
            }
        }

        if (null == hash) {
            System.out.println("No hash specified, using SHA256 by default.");
            hash = "SHA256";
        }

        if (null == keyFile) {
            System.out.println("Please specify the location of the wrapped key file.");
            help();
            return;
        }

        if (0 == keySize) {
            System.out.println("Please enter the size of the key in bits.");
            help();
            return;
        }

        if (null == unwrappingKeyFile) {
            System.out.println("Please specify the location of the RSA private key file that will be used to unwrap the AES key");
            help();
            return;
        }

        MGF1ParameterSpec paramSpec = null;
        switch (hash) {
            case "SHA1":
            case "SHA-1":
                transformation = "RSA/ECB/OAEPWithSHA-1ANDMGF1Padding";
                hash = "SHA-1";
                paramSpec = MGF1ParameterSpec.SHA1;
                break;
            case "SHA256":
            case "SHA-256":
                transformation = "RSA/ECB/OAEPWithSHA-256ANDMGF1Padding";
                hash = "SHA-256";
                paramSpec = MGF1ParameterSpec.SHA256;
                break;
        }

        if (null == transformation) {
            System.out.printf("%s is an unsupported hash\n", hash);
            help();
            return;
        }

        Path path = Paths.get(keyFile);
        byte[] wrappedBytes = Files.readAllBytes(path);
        if (wrappedBytes.length != keySize) {
            System.out.printf("Expected a key size of %d, but the wrapped key length was %d\n", keySize, wrappedBytes.length);
            help();
            return;
        }

        Key unwrappingKey = readPrivateKey(unwrappingKeyFile);

        OAEPParameterSpec spec = new OAEPParameterSpec(hash, "MGF1", paramSpec, PSource.PSpecified.DEFAULT);
        Cipher cipher = Cipher.getInstance(transformation, CloudHsmProvider.PROVIDER_NAME);
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, spec);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);
        if (null != unwrappedExtractableKey) {
            System.out.println("Your key has been unwrapped and imported");
        } else {
            System.out.println("Could not unwrap given key");
        }

    }

    private static void help() {
        System.out.println(helpString);
    }

    /**
     * Reads a private RSA key in PKCS8 format
     * @param filename The filename of the key
     * @return The RSA private key
     * @throws Exception
     */
    private static RSAPrivateKey readPrivateKey(String filename) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filename)), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

}

