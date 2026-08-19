/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.amazonaws.cloudhsm.jce.jni.MldsaAlgorithm;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;


/**
 * Demonstrates creating a CloudHSM KeyStore with an ML-DSA key pair.
 *
 * <p>The key pair is generated directly on the HSM via CloudHSM's KeyPairGenerator,
 * and a self-signed certificate is created using BouncyCastle with CloudHSM as the
 * signing provider.
 *
 * <p>Usage:
 * <pre>
 *   java MldsaKeyStoreExampleRunner --store keystore.store --password changeit
 *   java MldsaKeyStoreExampleRunner --store keystore.store --password changeit --algorithm ML-DSA-65
 *   java MldsaKeyStoreExampleRunner --store keystore.store --password changeit --label mykey --list
 * </pre>
 */
public class MldsaKeyStoreExampleRunner {

    private static final String DEFAULT_LABEL = "mldsa-example";
    private static final String DEFAULT_ALGORITHM = "ML-DSA-44";

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (final IOException ex) {
            System.out.println(ex);
            return;
        }

        String keystoreFile = null;
        String password = null;
        String label = DEFAULT_LABEL;
        String algorithm = DEFAULT_ALGORITHM;
        boolean list = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--store":
                    keystoreFile = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--label":
                    label = args[++i];
                    break;
                case "--algorithm":
                    algorithm = args[++i];
                    break;
                case "--list":
                    list = true;
                    break;
                case "--help":
                    printHelp();
                    return;
            }
        }

        if (keystoreFile == null || password == null) {
            printHelp();
            return;
        }

        if (list) {
            listKeys(keystoreFile, password);
            return;
        }

        createMldsaKeyStore(keystoreFile, password, label, algorithm);
    }

    /**
     * Creates an ML-DSA key pair on the HSM, builds a self-signed certificate,
     * and stores both in a CloudHSM KeyStore.
     */
    private static void createMldsaKeyStore(
            final String keystoreFile,
            final String password,
            final String label,
            final String algorithmName) throws Exception {

        final String privateLabel = label + ":Private";

        // Load or create the keystore
        final KeyStore keyStore =
                KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE);
        try {
            final FileInputStream in = new FileInputStream(keystoreFile);
            keyStore.load(in, password.toCharArray());
            in.close();
        } catch (final FileNotFoundException ex) {
            System.out.println("Keystore not found, creating new one.");
            keyStore.load(null, null);
        }

        if (keyStore.containsAlias(privateLabel)) {
            System.out.println("Key '" + privateLabel + "' already exists. Skipping creation.");
            return;
        }

        // 1. Generate ML-DSA key pair on the HSM
        System.out.println("Generating " + algorithmName + " key pair on HSM...");
        final MldsaAlgorithm mldsaAlgorithm = parseMldsaAlgorithm(algorithmName);

        final KeyAttributesMap additionalPublicAttrs = new KeyAttributesMap();
        additionalPublicAttrs.put(KeyAttribute.WRAP, false);
        additionalPublicAttrs.put(KeyAttribute.ENCRYPT, false);
        additionalPublicAttrs.put(KeyAttribute.TOKEN, true);

        final KeyAttributesMap additionalPrivateAttrs = new KeyAttributesMap();
        additionalPrivateAttrs.put(KeyAttribute.UNWRAP, false);
        additionalPrivateAttrs.put(KeyAttribute.DECRYPT, false);
        additionalPrivateAttrs.put(KeyAttribute.EXTRACTABLE, false);
        additionalPrivateAttrs.put(KeyAttribute.TOKEN, true);

        final KeyPair keyPair = AsymmetricKeys.generateMldsaKeyPair(
                mldsaAlgorithm, label, additionalPublicAttrs, additionalPrivateAttrs);
        System.out.println("Key pair generated.");

        // 2. Create self-signed certificate using BouncyCastle + CloudHSM signing
        System.out.println("Creating self-signed certificate...");
        final Certificate cert = createSelfSignedCertificate(keyPair);
        System.out.println("Certificate created.");

        // 3. Store in KeyStore
        System.out.println("Storing key and certificate in keystore...");
        // Use setKeyEntry directly instead of PrivateKeyEntry to avoid the algorithm
        // name mismatch check. CloudHSM returns "ML-DSA" from getAlgorithm() while
        // the certificate's public key algorithm is "ML-DSA-44" (from the OID).
        keyStore.setKeyEntry(
                privateLabel,
                keyPair.getPrivate(),
                password.toCharArray(),
                new Certificate[] {cert});

        final FileOutputStream out = new FileOutputStream(keystoreFile);
        keyStore.store(out, password.toCharArray());
        out.close();

        System.out.println("ML-DSA key pair and certificate stored in '" + keystoreFile
                + "' under alias '" + privateLabel + "'.");
    }

    /**
     * Creates a self-signed X.509 certificate using BouncyCastle for certificate
     * building and CloudHSM for the ML-DSA signature.
     */
    private static Certificate createSelfSignedCertificate(final KeyPair keyPair)
            throws Exception {

        final X500Name dn = new X500Name(
                "C=US, ST=Washington, L=Seattle, O=Amazon, OU=CloudHSM, CN=ML-DSA Test");
        final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        final Date now = new Date();
        final Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 365);
        final Date expiry = cal.getTime();

        final SubjectPublicKeyInfo pubKeyInfo =
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                dn, serial, now, expiry, dn, pubKeyInfo);

        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                false,
                new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils()
                        .createSubjectKeyIdentifier(pubKeyInfo));

        // BouncyCastle requires parameter-set-specific name (e.g. "ML-DSA-44").
        // Don't pin the provider -- when JCA tries initSign(cloudHsmPrivateKey),
        // only CloudHSM's provider accepts it; others throw InvalidKeyException.
        final String oid = pubKeyInfo.getAlgorithm().getAlgorithm().getId();
        final String signatureAlgorithm;
        switch (oid) {
            case "2.16.840.1.101.3.4.3.17":
                signatureAlgorithm = "ML-DSA-44";
                break;
            case "2.16.840.1.101.3.4.3.18":
                signatureAlgorithm = "ML-DSA-65";
                break;
            case "2.16.840.1.101.3.4.3.19":
                signatureAlgorithm = "ML-DSA-87";
                break;
            default:
                throw new IllegalArgumentException("Unknown ML-DSA OID: " + oid);
        }

        final ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(CloudHsmProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        final X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    /** Lists all aliases in the keystore. */
    private static void listKeys(final String keystoreFile, final String password)
            throws Exception {

        final KeyStore keyStore =
                KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE);
        try {
            final FileInputStream in = new FileInputStream(keystoreFile);
            keyStore.load(in, password.toCharArray());
            in.close();
        } catch (final FileNotFoundException ex) {
            System.out.println("Keystore not found.");
            return;
        }

        System.out.println("Aliases in keystore:");
        for (final Enumeration<String> aliases = keyStore.aliases();
                aliases.hasMoreElements(); ) {
            System.out.println("  " + aliases.nextElement());
        }
    }

    private static MldsaAlgorithm parseMldsaAlgorithm(final String name) {
        switch (name) {
            case "ML-DSA-44":
                return MldsaAlgorithm.MlDsa44;
            case "ML-DSA-65":
                return MldsaAlgorithm.MlDsa65;
            case "ML-DSA-87":
                return MldsaAlgorithm.MlDsa87;
            default:
                throw new IllegalArgumentException(
                        "Unsupported algorithm: " + name
                                + ". Use ML-DSA-44, ML-DSA-65, or ML-DSA-87.");
        }
    }

    private static void printHelp() {
        System.out.println(
                "MldsaKeyStoreExampleRunner\n"
                + "Creates a CloudHSM KeyStore with an ML-DSA key pair.\n\n"
                + "Options:\n"
                + "  --store <file>        Path to the keystore file\n"
                + "  --password <pass>     Keystore password\n"
                + "  --label <name>        Key label (default: mldsa-example)\n"
                + "  --algorithm <alg>     ML-DSA-44, ML-DSA-65, or ML-DSA-87 (default: ML-DSA-44)\n"
                + "  --list                List all aliases in the keystore\n"
                + "  --help                Show this message\n");
    }
}
