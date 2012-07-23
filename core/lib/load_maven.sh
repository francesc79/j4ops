#!/bin/bash


mvn install:install-file -DgroupId=at.tugraz.iaik -DartifactId=PKCS11-Wrapper -Dversion=1.2.18 -Dpackaging=jar -Dfile=iaikPkcs11Wrapper-1.2.18.jar
mvn install:install-file -DgroupId=com.jaccal -DartifactId=jaccal-core -Dversion=1.0.3 -Dpackaging=jar -Dfile=jaccal-core-1.0.3.jar

