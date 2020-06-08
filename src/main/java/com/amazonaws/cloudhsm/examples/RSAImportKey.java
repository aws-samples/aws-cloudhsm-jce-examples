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
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * This sample uses RSA OAEP padding to import a wrapped AES key.
 * You can test this sample by wrapping a key from the command line using OpenSSL. You must generate a keypair locally:
 *
 * ```
 *    $ openssl genrsa -out rsaprivate2048.pem 2048
 *    $ openssl rsa -pubout -in rsaprivate2048.pem -out rsapublic2048.pem
 *```

 * Then you must import the private key using the Key Management Util (https://docs.aws.amazon.com/cloudhsm/latest/userguide/key_mgmt_util-importPrivateKey.html).
 *
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
 */
public class RSAImportKey {
    private static String helpString = "RSAImportKey\n" +
            "This tool uses an RSA private key to unwrap an AES key. The AES key must have been wrapped with OAEP padding\n" +
            "\n" +
            "Options\n" +
            "\t--hash\t\t\tType of hash used to wrap [SHA1, SHA256(default)].\n" +
            "\t--key-size\t\tSize of the wrapping key in bits [2048, 4096].\n" +
            "\t--wrapped-key\t\tLocation of AES Wrapped key.\n" +
            "\t--unwrapping-key-handle\tHandle of unwrapping key.\n";

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String keyFile = null;
        String hash = null;
        String transformation = null;
        Integer keySize = 0;
        Integer unwrappingKeyHandle = 0;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--unwrapping-key-handle":
                    unwrappingKeyHandle = Integer.valueOf(args[++i]);
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

        if (0 == unwrappingKeyHandle) {
            System.out.println("Please enter the handle of the RSA private key used to unwrap your AES key.");
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

        CaviumKey unwrappingKey = getKeyByHandle(unwrappingKeyHandle);
        if (null == unwrappingKey) {
            System.out.printf("Could not find a key for handle %d\n", unwrappingKeyHandle);
            help();
            return;
        }

        OAEPParameterSpec spec = new OAEPParameterSpec(hash, "MGF1", paramSpec, PSource.PSpecified.DEFAULT);
        Cipher cipher = Cipher.getInstance(transformation, "Cavium");
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, spec);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);
        System.out.printf("Your key has been imported.\n");
        System.out.printf("The handle is %d\n", ((CaviumKey) unwrappedExtractableKey).getHandle());
        Util.persistKey((CaviumKey) unwrappedExtractableKey);

    }

    /**
     * Get an existing key from the HSM using a key handle.
     * @param handle The key handle in the HSM.
     * @return CaviumKey object
     */
    private static CaviumKey getKeyByHandle(long handle) throws CFM2Exception {
        // There is no direct method to load a key, but there is a method to load key attributes.
        // Using the key attributes and the handle, a new CaviumKey object can be created. This method shows
        // how to create a specific key type based on the attributes.
        byte[] keyAttribute = Util.getKeyAttributes(handle);
        CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);

        if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
            CaviumAESKey aesKey = new CaviumAESKey(handle, cka);
            return aesKey;
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
            CaviumRSAPrivateKey privKey = new CaviumRSAPrivateKey(handle, cka);
            return privKey;
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
            CaviumRSAPublicKey pubKey = new CaviumRSAPublicKey(handle, cka);
            return pubKey;
        } else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_GENERIC_SECRET) {
            CaviumKey key = new CaviumAESKey(handle, cka);
            return key;
        }

        return null;
    }

    private static void help() {
        System.out.println(helpString);
    }

}
