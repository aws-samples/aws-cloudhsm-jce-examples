# aws-cloudhsm-jce-examples

These sample applications demonstrate how to use the JCE with CloudHSM. They show basic functionality,
as well as best practices regarding performance.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Building the examples

### Dependencies

The latest version of CloudHSM Client and JCE dependencies are required.
They should be installed using the official procedures documented here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html

The examples are tested on a fresh Amazon Linux 2 AMI. You will need to have the following packages 
installed:

* OpenJDK 8
* Apache Maven 3.0.5

You can install these packages on Amazon Linux 2 by running

```
sudo yum install -y java maven
```

If you are running on Amazon Linux 1, you will need to install extra packages to get Maven.
You can follow these instructions to build the samples on Amazon Linux 1:

```
# Maven is only available through extra packages
sudo wget http://repos.fedorapeople.org/repos/dchen/apache-maven/epel-apache-maven.repo -O /etc/yum.repos.d/epel-apache-maven.repo
sudo sed -i s/\$releasever/6/g /etc/yum.repos.d/epel-apache-maven.repo

# You will need Java 1.8 to build the samples
sudo yum install -y java-1.8.0-openjdk-devel
sudo yum install -y apache-maven

# When updating alternatives, choose the 1.8 path: /usr/lib/jvm/jre-1.8.0-openjdk.x86_64/bin/java
sudo update-alternatives --config java
```


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
java -ea -Djava.library.path=/opt/cloudhsm/lib/ -jar target/assembly/login-runner.jar --help
```

## Running and verifying all the samples

To run and verify all the samples together, run the command ```mvn verify```
