# aws-cloudhsm-jce-examples

These sample applications demonstrate how to use the JCE with CloudHSM. They show basic functionality, as well as best practices regarding performance.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Building the examples

### Dependencies

The latest SDK5 version of CloudHSM JCE is required. They should be installed using the [official procedures](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html)

The examples are tested on Amazon Linux 2 and Amazon Linux 2023. You will need to have the following packages installed:

* OpenJDK 17
* Apache Maven 3.0.5

You can install these packages on Amazon Linux 2 (or Amazon Linux 2023) by running

```sh
sudo yum install -y java-17-amazon-corretto-devel maven
```

### Building

You can build the project using Maven. Maven will copy the required CloudHSM jars into a local repository and build fat jars which can be executed from the command line. These fat jars will be placed in the
`target/assembly/` directory.

Before you build your project, be sure to enter the correct CloudHSM version number based on which CloudHSM JCE Provider you have installed on your system. By default, this project is set to use the latest available CloudHSM version, and  you may need to make modifications if you are running an older version (note that not all tests are guaranteed to work with older versions of the client). To do this, modify the following line in the `pom.xml` to match your version:

```sh
<cloudhsmVersion>5.18.0</cloudhsmVersion>
```

To build the project, use the following command:

```sh
mvn validate
mvn clean package
```

## Running the samples

You will need to have a CloudHSM Client connected to an ACTIVE cluster. For more details, please follow the official instructions for [Getting started with AWS CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html)

You will need to provide credentials to the JCE provider in order to run the samples. Please see [Provide credentials to the JCE provider](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html#java-library-credentials_5)

All Java dependencies should be bundled in the fat jars. Jars can be run using the following command line (as an example):

```sh
java -ea -jar target/assembly/login-runner.jar --help
```

Note that sample `desecb-runner.jar` and `cbc-runner.jar` are expected to fail if your cluster has the `hsm2m.medium` HSM type and is in FIPS mode, because the corresponding mechanisms are deprecated. Note that samples `eddsaops-runner.jar` and `eddsa-import-runner.jar` are expected to fail if cluster has the `hsm1.medium` HSM type or is in FIPS mode. For more information on this, see the CloudHSM [public doc](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-samples.html#java-samples-code-5-note-1)

## Running and verifying all the samples

To run and verify all the samples together, run the command ```mvn verify```

## Running with Oracle JDK

The default `java -jar` invocation uses fat JARs built by the Maven shade plugin. These fat JARs are **not compatible with Oracle JDK** because the shade plugin repackages the signed CloudHSM provider classes into an unsigned JAR. Oracle JDK enforces JCE provider signing for `javax.crypto` operations (Cipher, Mac, KeyGenerator, KeyAgreement) and will reject unsigned provider JARs with:

```
java.security.NoSuchProviderException: JCE cannot authenticate the provider CloudHSM
```

Note that `java.security` operations (Signature, KeyPairGenerator) are not affected — only `javax.crypto` operations require JCE provider signing on Oracle JDK.

To run the samples on Oracle JDK, use `-cp` instead of `-jar` so the signed CloudHSM JAR is loaded directly:

```sh
mvn package
mvn dependency:copy-dependencies
java -ea \
    -Djava.library.path=/opt/cloudhsm/lib \
    -cp "target/classes:target/dependency/*" \
    com.amazonaws.cloudhsm.examples.AESGCMEncryptDecryptRunner \
    --method environment --user <cu_user> --password <cu_pass>
```

Replace the main class name with the runner for the sample you want to run. The main class for each sample follows the pattern `com.amazonaws.cloudhsm.examples.<RunnerClassName>` — you can find the runner class name in the corresponding source file under `src/main/java/com/amazonaws/cloudhsm/examples/`.

**For your own applications:** If you are using Oracle JDK, do not repackage `cloudhsm-jce-*.jar` into a fat/uber JAR (Maven shade, Gradle shadow, Spring Boot fat JAR, etc.). Keep it as a separate JAR on the classpath.
