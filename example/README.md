# Ubiq Security Sample Application using Java Library

Provided are two sample applications. One called "UbiqSample.java" demonstrates how to encrypt and decrypt typical data that you might
encounter in your own applications. The other sample application called "UbiqSampleFPE.java" demonstrates how to encrypt and decrypt
using format preserving encryption (FPE).


## Documentation for UbiqSample.java

See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build From Source

Use gradlew to compile the sample application

```sh
#Linux / Mac
cd example
./gradlew clean assemble build --refresh-dependencies
```
```dos
# Windows
cd example
.\gradlew clean assemble build --refresh-dependencies
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

```sh
[default]
ACCESS_KEY_ID = ...
SECRET_SIGNING_KEY = ...
SECRET_CRYPTO_ACCESS_KEY = ...
```
## View Program Options

From within the example directory, use the ```java ``` command to execute the sample application

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -h
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -h
</pre>

<pre>
Usage: Ubiq Security Example [options]
  Options:
    --creds, -c
      Set the file name with the API credentials
    --decrypt, -d
      Decrypt the contents of the input file and write the results to output
      file
      Default: false
    --encrypt, -e
      Encrypt the contents of the input file and write the results to output
      file
      Default: false
    --help, -h
      Print app parameter summary
  * --in, -i
      Set input file name
  * --out, -o
      Set output file name
    --piecewise, -p
      Use the piecewise encryption / decryption interfaces
      Default: false
    --profile, -P
      Identify the profile within the credentials file
      Default: default
    --simple, -s
      Use the simple encryption / decryption interfaces
      Default: false
    --version, -v
      Print the app version
      Default: false
</pre>


#### Demonstrate using the simple (-s / --simple) API interface to encrypt this README.md file and write the encrypted data to readme.enc

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -s -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -s -c credentials
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to decrypt the readme.enc file and write the decrypted output to README.out

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -s -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -s -c credentials
</pre>

#### Demonstrate using the piecewise (-p / --piecewise) API interface to encrypt this README.md file and write the encrypted data to readme.enc

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -p -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -p -c credentials
</pre>

#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the readme.enc file and write the decrypted output to README.out

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -p -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -p -c credentials
</pre>




## Documentation for UbiqSampleFPE.java
Format preserving encryption (FPE/eFPE) is an optionally available feature. Please contact support@ubiqsecurity.com to add this capability to your account.


See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build From Source

Use gradlew to compile the sample application

```sh
#Linux / Mac
cd example
./gradlew clean assemble build --refresh-dependencies
```
```dos
# Windows
cd example
.\gradlew clean assemble build --refresh-dependencies
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard. Do make sure that you have the FPE option enabled in the Ubiq dashboard.

```sh
[default]
ACCESS_KEY_ID = ...
SECRET_SIGNING_KEY = ...
SECRET_CRYPTO_ACCESS_KEY = ...
```
## View Program Options

From within the example directory, use the ```java ``` command to execute the sample application

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSampleFPE  -h
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSampleFPE  -h
</pre>

<pre>
Usage: Ubiq Security Example [options]
  Options:
    --bulk, -b
      Use the bulk encryption / decryption interfaces
    --creds, -c
      Set the file name with the API credentials
    --decrypttext, -d
      Set the cipher text value to decrypt and will return the decrypted text.
    --encrypttext, -e
      Set the field text value to encrypt and will return the encrypted cipher
      text.
  * --ffsname, -n
      Set the ffs name, for example SSN.
    --help, -h
      Print app parameter summary
    --profile, -P
      Identify the profile within the credentials file
      Default: default
    --simple, -s
      Use the simple encryption / decryption interfaces
    --version, -V
      Show program's version number and exit
</pre>



#### Demonstrate encrypting a social security number and returning a cipher text

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSampleFPE  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN' -s
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSampleFPE  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN' -s
</pre>

#### Demonstrate decrypting a social security number and returning the plain text

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSampleFPE  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN' -s
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSampleFPE  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN' -s
</pre>
