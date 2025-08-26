# aws-cloudhsm-jce-examples

These sample applications demonstrate how to use the JCE with CloudHSM. They show basic functionality,
as well as best practices regarding performance.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Building the examples

### Dependencies

The latest SDK5 version of CloudHSM JCE is required.
They should be installed using the official procedures documented here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html

The examples are tested on Amazon Linux 2 and Amazon Linux 2023. You will need to have the following packages 
installed:

* OpenJDK 17
* Apache Maven 3.0.5

You can install these packages on Amazon Linux 2 (or Amazon Linux 2023) by running

```
sudo yum install -y java-17-amazon-corretto-devel maven
```

### Building

You can build the project using Maven. Maven will copy the required CloudHSM jars into a local repository
and build fat jars which can be executed from the command line. These fat jars will be placed in the
`target/assembly/` directory. 

Before you build your project, be sure to enter the correct CloudHSM version number based on which CloudHSM JCE Provider
you have installed on your system. By default, this project is set to use the latest available CloudHSM version, and 
you may need to make modifications if you are running an older version (note that not all tests are guaranteed to work 
with older versions of the client). To do this, modify the following line in the `pom.xml` to match your version:

```
<cloudhsmVersion>5.16.1</cloudhsmVersion>
```


To build the project, use the following command:

```
mvn validate
mvn clean package
```

## Running the samples

You will need to have a CloudHSM Client connected to an ACTIVE cluster. For more details, please follow
the official instructions here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html

You will need to provide credentials to the JCE provider in order to run the samples. Please read about
JCE provider credentials here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install_5.html#java-library-credentials_5

All Java dependencies should be bundled in the fat jars.
Jars can be run using the following command line (as an example):

```
java -ea -jar target/assembly/login-runner.jar --help
```

Note that sample `desecb-runner.jar` and `cbc-runner.jar` are expected to fail in clusters in FIPS mode
because the corresponding mechanisms are deprecated.

## Running and verifying all the samples

To run and verify all the samples together, run the command ```mvn verify```
