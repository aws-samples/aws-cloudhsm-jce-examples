# aws-cloudhsm-jce-examples

These sample applications demonstrate how to use the JCE with CloudHSM. They show basic functionality,
as well as best practices regarding performance.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Building the examples

### Dependencies

The examples are tested on an fresh Amazon Linux 2 AMI. You will need to have the following packages 
installed:

* OpenJDK 8
* Apache Maven 3.0.5

You can install these packages on Amazon Linux 2 by running

```
sudo yum install -y java maven
```

The CloudHSM Client and JCE dependencies are also required. They should be installed using the official
procedures documented here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html


### Building

You can build the project using Maven. Maven will copy the required CloudHSM jars into a local repository
and build fat jars which can be executed from the command line. These fat jars will be placed in the
`target/assembly/` directory. To build the project, use the following command:

```
mvn validate
mvn clean package
```

## Running the samples

You will need to have a CloudHSM Client connected to an ACTIVE cluster. For more details, please follow
the official instructions here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html

All Java dependencies should be bundled in the fat jars. You will only need to specify the location of the
native library in `/opt/cloudhsm/lib`. Jars can be run using the following command line (as an example): 

```
java -Djava.library.path=/opt/cloudhsm/lib/ -jar target/assembly/login-runner.jar --help
```