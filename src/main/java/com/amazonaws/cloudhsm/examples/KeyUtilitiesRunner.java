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
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyType;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * This sample demonstrates how to work with keys. This could be importing keys, exporting keys, loading keys by handle,
 * or deleting keys.
 */
public class KeyUtilitiesRunner {
    private static String helpString = "KeyUtilitiesRunner\n" +
            "This sample demonstrates the different utility methods for working with keys in the HSM.\n" +
            "\n" +
            "Options\n" +
            "\t[--label <key label>]\n" +
            "\t[--keytype\t\t\tSelect a keytype from {AES, DESEDE, EC, GENERIC_SECRET, RSA}]\n" +
            "\t--get-key\t\tGet information about a key in the HSM\n" +
            "\t--delete-key\t\tDelete a key from the HSM\n" +
            "\t--import-key\t\tGenerates a key locally and imports it into the HSM\n" +
            "\t--import-rsa-pem\t\tRead a PEM file and import the private key\n\n";

    private enum modes {
        INVALID,
        GET_KEY,
        DELETE_KEY,
        IMPORT_KEY,
        IMPORT_PEM
    }

    private static String formatStringForKeyDetails = "%-12s%-12s%-12s%-12s%-12s%s\n";

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String label = null;
        String keyTypeString = null;
        String pemFile = null;
        modes mode = modes.INVALID;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--label":
                    label = args[++i];
                    break;
                case "--keytype":
                    keyTypeString = args[++i];
                    break;
                case "--get-key":
                    mode = modes.GET_KEY;
                    break;
                case "--delete-key":
                    mode = modes.DELETE_KEY;
                    break;
                case "--import-key":
                    mode = modes.IMPORT_KEY;
                    break;
                case "--import-rsa-pem":
                    pemFile = args[++i];
                    mode = modes.IMPORT_PEM;
                    break;
            }
        }
        KeyType keyType = null;
        if (keyTypeString !=null) {
            switch (keyTypeString) {
                case "AES":
                    keyType = KeyType.AES;
                    break;
                case "DESEDE":
                    keyType = KeyType.DESEDE;
                    break;
                case "EC":
                    keyType = KeyType.EC;
                    break;
                case "GENERIC_SECRET":
                    keyType = KeyType.GENERIC_SECRET;
                    break;
                case "RSA":
                    keyType = KeyType.RSA;
                    break;
                default:
                    System.out.println("Invalid Key Type. Please use the correct key type\n");
                    help();
                    return;
            }
        }
        switch (mode) {
            case IMPORT_PEM: {
                Path path = Paths.get(pemFile);
                byte[] pem = Files.readAllBytes(path);
                Key privKey = readPem(pem);
                importRsaKey(privKey, "RSA Import PEM Test");
                break;
            }
            case IMPORT_KEY: {
                // Generate a 256-bit AES symmetric key.
                // This key is not yet in the HSM. It will have to be imported using a KeyAttributesMap.
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(256);
                Key keyToBeImported = kg.generateKey();

                // Import the key as an ephemeral key.
                // You can use the key label to identify the key in other operations.
                importAesKey(keyToBeImported, "Test");
                break;
            }
            case GET_KEY: {
                Key key = null;
                if (keyType == null) {
                    // We only have label to find a key
                    key = getKeyByLabel(label);
                } else {
                    // We have additional attributes which we can use to find a key
                    key = getKeyByUsingAttributesMap(label, keyType);
                }
                if (null != key) {
                    System.out.println("Fetched key with label: " + label);
                } else {
                    System.out.println("Could not find the given key label " + label);
                }
                break;
            }
            case DELETE_KEY: {
                deleteKey(label);
                break;
            }
        }
    }

    private static void help() {
        System.out.println(helpString);
    }

    /**
     * Get an existing key from the HSM using a key label.
     * @param label The key label in the HSM.
     * @return Key object
     */
    private static Key getKeyByLabel(String label)
        throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
        UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keystore.load(null, null);
        return keystore.getKey(label, null);
    }

    /**
     * Get an existing key from the HSM using a key label and some extra attributes.
     * @param label The key label in the HSM.
     * @return Key object
     */
    private static Key getKeyByUsingAttributesMap(String label, KeyType keyType)
        throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
        UnrecoverableKeyException, AddAttributeException, InvalidKeySpecException {
        KeyAttributesMap findSpec = new KeyAttributesMap();
        findSpec.put(KeyAttribute.LABEL, label);
        if (keyType !=null) {
            findSpec.put(KeyAttribute.KEY_TYPE, keyType);
        }
        // You could also use additional attributes such as ObjectClassType, key size, etc. to filter
        // even further.
        KeyStoreWithAttributes keyStore = KeyStoreWithAttributes.getInstance("CloudHSM");
        /**
         * We will load an empty keystore here as we just want to find a key on the HSM.
         * But we could also use local keystore file and use this keystore as a regular
         * keystore as well.
         */
        keyStore.load(null, null);
        return keyStore.getKey(findSpec);
    }

    /**
     * Delete a key by label.
     * @param label The key label in the HSM.
     */
    private static void deleteKey(String label)
        throws UnrecoverableKeyException, CertificateException, IOException,
        NoSuchAlgorithmException, KeyStoreException, DestroyFailedException {
        Key keyToBeDeleted = getKeyByLabel(label);
        ((Destroyable) keyToBeDeleted).destroy();
    }

    /**
     * Import a RSA key into the HSM.
     * @param key Key object.
     * @param keyLabel Label to store with the key.
     */
    private static Key importRsaKey(Key key, String keyLabel)
        throws AddAttributeException {
        if (!(key instanceof RSAPrivateCrtKey)) {
            return null;
        }
        // Create a new key spec to identify the key and specify a label.
        RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
        // Add key data for the key to be imported
        KeyAttributesMap keySpec = new KeyAttributesMapBuilder()
            .put(KeyAttribute.MODULUS, rsaKey.getModulus().toByteArray())
            .put(KeyAttribute.PRIVATE_EXPONENT, rsaKey.getPrivateExponent().toByteArray())
            .put(KeyAttribute.PUBLIC_EXPONENT, rsaKey.getPublicExponent().toByteArray())
            .put(KeyAttribute.PRIME_P, rsaKey.getPrimeP().toByteArray())
            .put(KeyAttribute.PRIME_Q, rsaKey.getPrimeQ().toByteArray())
            .put(KeyAttribute.PRIME_EXPONENT_P, rsaKey.getPrimeExponentP().toByteArray())
            .put(KeyAttribute.PRIME_EXPONENT_Q, rsaKey.getPrimeExponentQ().toByteArray())
            .put(KeyAttribute.CRT_COEFFICIENT, rsaKey.getCrtCoefficient().toByteArray())
            .build();

        // Add additional key related attributes
        keySpec.put(KeyAttribute.LABEL, keyLabel);

        // The imported key will be ephemeral; it will be deleted from the HSM when the
        // application exits. To persist the key you must set this attribute to true.
        keySpec.put(KeyAttribute.TOKEN, false);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", CloudHsmProvider.PROVIDER_NAME);
            PrivateKey importedKey = keyFactory.generatePrivate(keySpec);
            return importedKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Import an AES key into the HSM.
     * @param key Key object.
     * @param keyLabel Label to store with the key.
     */
    private static Key importAesKey(Key key, String keyLabel)
        throws AddAttributeException {
        if (!(key instanceof SecretKey)) {
            return null;
        }
        // Create a new key spec to identify the key and specify a label
        SecretKey aesKey = (SecretKey) key;
        // Add key data for the key to be imported
        KeyAttributesMap keySpec = new KeyAttributesMapBuilder()
            .put(KeyAttribute.VALUE, aesKey.getEncoded())
            .build();

        // Add additional key related attributes
        keySpec.put(KeyAttribute.LABEL, keyLabel);

        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES", CloudHsmProvider.PROVIDER_NAME);
            SecretKey importedKey = keyFactory.generateSecret(keySpec);
            return importedKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Import a PEM file with a PKCS#8 encoded key. You can generate this PEM file with OpenSSL.
     * openssl genrsa -out priv.pem 2048
     * openssl pkcs8 -topk8 -in priv.pem -inform pem -out priv_pkcs8.pem -outform pem -nocrypt
     * @param pem
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws UnsupportedEncodingException
     */
    private static Key readPem(byte[] pem) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String privateKeyPEM = new String(pem, "ASCII");
        privateKeyPEM = privateKeyPEM.replaceAll("^-----BEGIN .* KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replaceAll("-----END .* KEY-----$", "");

        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);
        try {
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
            return privateKey;
        } catch (InvalidKeySpecException e) {
            System.out.printf("Exception while creating KeySpec. Is your key stored in PKCS#8 format?\n\n");
        }
        return null;
    }
}
