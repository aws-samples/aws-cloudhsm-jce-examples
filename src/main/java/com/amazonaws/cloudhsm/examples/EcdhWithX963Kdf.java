package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.EcParams;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

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

public class EcdhWithX963Kdf {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }

            // Generate Party A's key pair
            System.out.println("\nGenerating Party A's EC Key Pair...");
            KeyAttributesMap privateKeyAttributes = new KeyAttributesMap();
            privateKeyAttributes.put(KeyAttribute.DERIVE, true);
            KeyPair partyAKeys = AsymmetricKeys.generateECKeyPair(
                    EcParams.EC_CURVE_PRIME256,
                    "party-a-key",
                    new KeyAttributesMap(),
                    privateKeyAttributes
            );

            // Generate Party B's key pair
            System.out.println("Generating Party B's EC Key Pair...");
            KeyPair partyBKeys = AsymmetricKeys.generateECKeyPair(
                    EcParams.EC_CURVE_PRIME256,
                    "party-b-key",
                    new KeyAttributesMap(),
                    privateKeyAttributes
            );

            // Party A derives key using B's public key
            System.out.println("\nParty A deriving shared secret using Party B's public key...");
            KeyAttributesMap derivedKeyAttributes = new KeyAttributesMap();
            derivedKeyAttributes.put(KeyAttribute.SIZE, 256);

            // Supported Key Agreement Functions can be found here : https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported_5.html#java-key-derivation_5
            String algorithm = "ECDHwithX963SHA256KDF";
            KeyAgreement partyAKeyAgreement = KeyAgreement.getInstance(algorithm, CloudHsmProvider.PROVIDER_NAME);
            partyAKeyAgreement.init(partyAKeys.getPrivate(), derivedKeyAttributes);
            partyAKeyAgreement.doPhase(partyBKeys.getPublic(), true);
            SecretKey partyADerivedKey = partyAKeyAgreement.generateSecret("AES");

            // Party B derives key using A's public key
            System.out.println("Party B deriving shared secret using Party A's public key...");
            KeyAgreement partyBKeyAgreement = KeyAgreement.getInstance(algorithm, CloudHsmProvider.PROVIDER_NAME);
            partyBKeyAgreement.init(partyBKeys.getPrivate(), derivedKeyAttributes);
            partyBKeyAgreement.doPhase(partyAKeys.getPublic(), true);
            SecretKey partyBDerivedKey = partyBKeyAgreement.generateSecret("AES");

            // Test the derived keys with encryption/decryption
            String plaintext = "Test message for ECDH key agreement demonstration";
            byte[] plaintextBytes = plaintext.getBytes();
            String aad = "Additional authenticated data";
            byte[] aadBytes = aad.getBytes();

            System.out.println("\nValidating key agreement with AES-GCM encryption/decryption:");
            System.out.println("Original message: " + plaintext);
            System.out.println("AAD: " + aad);

            // Party A encrypts
            System.out.println("\nParty A encrypting with their derived key...");
            Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, partyADerivedKey);
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
            decryptCipher.init(Cipher.DECRYPT_MODE, partyBDerivedKey, spec);
            decryptCipher.updateAAD(aadBytes);
            byte[] decrypted = decryptCipher.doFinal(ciphertext);

            System.out.println("Decrypted message: " + new String(decrypted));
            System.out.println("\nKey Agreement Validation: " + 
                (plaintext.equals(new String(decrypted)) ? 
                "SUCCESS - Both parties derived the same key and successfully encrypted/decrypted the message" : 
                "FAILED - Keys do not match"));

        } catch (Exception e) {
            System.err.println("Operation failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}