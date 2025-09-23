package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.EcParams;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.spec.EcdhWithX963KdfParamSpec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;

public class EcdhWithX963Kdf {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }

            System.out.println("AWS CloudHSM ECDH with X963 KDF Examples");
            System.out.println("=========================================\n");

            // Demonstrate basic ECDH with KDF
            ecdhWithKdf();

            System.out.println("\n" + "=".repeat(50) + "\n");

            // Demonstrate ECDH with KDF and sharedInfo
            ecdhWithKdfAndSharedInfo();

        } catch (Exception e) {
            System.err.println("Operation failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void ecdhWithKdf() throws Exception {
        System.out.println("1. Basic ECDH with X963 KDF");
        System.out.println("----------------------------");

        KeyPair[] keyPairs = generateKeyPairs("party-a-key", "party-b-key");
        SecretKey[] derivedKeys = performEcdhKeyAgreement(keyPairs[0], keyPairs[1], null);
        validateKeyAgreement(derivedKeys[0], derivedKeys[1], 
            "Test message for ECDH key agreement demonstration", 
            "Additional authenticated data",
            "SUCCESS - Both parties derived the same key and successfully encrypted/decrypted the message");
    }

    private static void ecdhWithKdfAndSharedInfo() throws Exception {
        System.out.println("2. ECDH with X963 KDF and SharedInfo");
        System.out.println("------------------------------------");

        KeyPair[] keyPairs = generateKeyPairs("party-a-shared-key", "party-b-shared-key");
        
        // Define shared context information
        byte[] sharedInfo = "Protocol:TLS1.3|Session:ABC123".getBytes(StandardCharsets.UTF_8);
        System.out.println("\nSharedInfo: " + new String(sharedInfo));

        SecretKey[] derivedKeys = performEcdhKeyAgreement(keyPairs[0], keyPairs[1], sharedInfo);
        boolean success = validateKeyAgreement(derivedKeys[0], derivedKeys[1], 
            "Test message for ECDH with SharedInfo demonstration", 
            "Additional authenticated data with SharedInfo",
            "SUCCESS - Both parties derived the same key with SharedInfo and successfully encrypted/decrypted the message");

        if (success) {
            System.out.println("SUCCESS - SharedInfo was properly incorporated into key derivation");
        }
    }

    private static KeyPair[] generateKeyPairs(String partyALabel, String partyBLabel) throws Exception {
        // Generate Party A's key pair
        System.out.println("\nGenerating Party A's EC Key Pair...");
        KeyAttributesMap privateKeyAttributes = new KeyAttributesMap();
        privateKeyAttributes.put(KeyAttribute.DERIVE, true);
        KeyPair partyAKeys = AsymmetricKeys.generateECKeyPair(
                EcParams.EC_CURVE_PRIME256,
                partyALabel,
                new KeyAttributesMap(),
                privateKeyAttributes
        );

        // Generate Party B's key pair
        System.out.println("Generating Party B's EC Key Pair...");
        KeyPair partyBKeys = AsymmetricKeys.generateECKeyPair(
                EcParams.EC_CURVE_PRIME256,
                partyBLabel,
                new KeyAttributesMap(),
                privateKeyAttributes
        );

        return new KeyPair[]{partyAKeys, partyBKeys};
    }

    private static SecretKey[] performEcdhKeyAgreement(KeyPair partyAKeys, KeyPair partyBKeys, byte[] sharedInfo) throws Exception {
        KeyAttributesMap derivedKeyAttributes = new KeyAttributesMap();
        derivedKeyAttributes.put(KeyAttribute.SIZE, 256);

        // Supported Key Agreement Functions can be found here : https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported_5.html#java-key-derivation_5
        String algorithm = "ECDHwithX963SHA256KDF";

        // Party A derives key using B's public key
        System.out.println(sharedInfo != null ? 
            "\nParty A deriving shared secret using Party B's public key with SharedInfo..." :
            "\nParty A deriving shared secret using Party B's public key...");
        KeyAgreement partyAKeyAgreement = KeyAgreement.getInstance(algorithm, CloudHsmProvider.PROVIDER_NAME);
        if (sharedInfo != null) {
            EcdhWithX963KdfParamSpec paramSpecA = new EcdhWithX963KdfParamSpec(sharedInfo, derivedKeyAttributes);
            partyAKeyAgreement.init(partyAKeys.getPrivate(), paramSpecA);
        } else {
            partyAKeyAgreement.init(partyAKeys.getPrivate(), derivedKeyAttributes);
        }
        partyAKeyAgreement.doPhase(partyBKeys.getPublic(), true);
        SecretKey partyADerivedKey = partyAKeyAgreement.generateSecret("AES");

        // Party B derives key using A's public key
        System.out.println(sharedInfo != null ? 
            "Party B deriving shared secret using Party A's public key with SharedInfo..." :
            "Party B deriving shared secret using Party A's public key...");
        KeyAgreement partyBKeyAgreement = KeyAgreement.getInstance(algorithm, CloudHsmProvider.PROVIDER_NAME);
        if (sharedInfo != null) {
            EcdhWithX963KdfParamSpec paramSpecB = new EcdhWithX963KdfParamSpec(sharedInfo, derivedKeyAttributes);
            partyBKeyAgreement.init(partyBKeys.getPrivate(), paramSpecB);
        } else {
            partyBKeyAgreement.init(partyBKeys.getPrivate(), derivedKeyAttributes);
        }
        partyBKeyAgreement.doPhase(partyAKeys.getPublic(), true);
        SecretKey partyBDerivedKey = partyBKeyAgreement.generateSecret("AES");

        return new SecretKey[]{partyADerivedKey, partyBDerivedKey};
    }

    private static boolean validateKeyAgreement(SecretKey partyAKey, SecretKey partyBKey, String plaintext, String aad, String successMessage) throws Exception {
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] aadBytes = aad.getBytes();

        System.out.println("\nValidating key agreement with AES-GCM encryption/decryption:");
        System.out.println("Original message: " + plaintext);
        System.out.println("AAD: " + aad);

        // Party A encrypts
        System.out.println("\nParty A encrypting with their derived key...");
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, partyAKey);
        encryptCipher.updateAAD(aadBytes);
        byte[] ciphertext = encryptCipher.doFinal(plaintextBytes);
        byte[] iv = encryptCipher.getIV();

        System.out.println("\nEncryption details:");
        System.out.println("IV (" + iv.length + " bytes): " + bytesToHex(iv));
        System.out.println("Encrypted text (" + (ciphertext.length - GCM_TAG_LENGTH) + " bytes): " + 
                         bytesToHex(Arrays.copyOfRange(ciphertext, 0, ciphertext.length - GCM_TAG_LENGTH)));
        System.out.println("Authentication tag (" + GCM_TAG_LENGTH + " bytes): " + 
                         bytesToHex(Arrays.copyOfRange(ciphertext, ciphertext.length - GCM_TAG_LENGTH, ciphertext.length)));

        // Party B decrypts
        System.out.println("\nParty B decrypting with their derived key...");
        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        decryptCipher.init(Cipher.DECRYPT_MODE, partyBKey, spec);
        decryptCipher.updateAAD(aadBytes);
        byte[] decrypted = decryptCipher.doFinal(ciphertext);

        System.out.println("Decrypted message: " + new String(decrypted));
        boolean success = plaintext.equals(new String(decrypted));
        System.out.println("\nKey Agreement Validation: " + (success ? successMessage : "FAILED - Keys do not match"));
        return success;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}