# Vonage JWT JDK Library

![Java](https://img.shields.io/badge/java-8%2B-red)
[![Maven Central](https://img.shields.io/maven-central/v/com.vonage/jwt.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22com.vonage%22%20AND%20a:%22jwtr%22)
[![codecov](https://codecov.io/gh/Vonage/vonage-jwt-jdk/graph/badge.svg)](https://codecov.io/gh/Vonage/vonage-jwt-jdk)
[![Build Status](https://github.com/Vonage/vonage-jwt-jdk/actions/workflows/build.yml/badge.svg)](https://github.com/Vonage/vonage-jwt-jdk/actions/workflows/build.yml)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This library provides a wrapper for generating JWTs using Vonage-specific claims.

Learn more about [Authenticating with JSON Web Tokens](https://developer.vonage.com/concepts/guides/authentication#json-web-tokens-jwt).

## Installation

For Gradle:

```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.vonage:jwt:1.1.3'
}
```

For Maven:

```xml
<dependency>
  <groupId>com.vonage</groupId>
  <artifactId>jwt</artifactId>
  <version>1.1.3</version>
</dependency>
```

## Usage

The JWT library provides a `Jwt.Builder` which can be used to construct a `Jwt` representation. The `Jwt` class contains a `generate()` method for generating JSON Web Signatures that can then be used to authenticate with the API.

### Generating a JWT

The API requires an `application_id` claim, and the token needs to be signed with a private key. The corresponding public key is uploaded to Vonage for signature verification. The library expects you to provide a `PKCS#8` key contents or file path.

#### Generating a JWT with Private Key Contents

To generate a JWT with these properties you can use:

##### Kotlin

```kotlin
val jws = Jwt.builder()
    .applicationId("your-application-id")
    .privateKeyContents("private key contents")
    .build()
    .generate()
```

##### Java

```java
String jws = Jwt.builder()
        .applicationId("your-application-id")
        .privateKeyContents("private key contents")
        .build()
        .generate();
```

#### Generating a JWT with Private Key Path

You can also provide a `Path` to the location of your private key:

##### Kotlin

```kotlin
val jws = Jwt.builder()
    .applicationId("your-application-id")
    .privateKeyPath(Paths.get("/path/to/private.key"))
    .build()
    .generate()
```

##### Java

```java
String jws = Jwt.builder()
        .applicationId("your-application-id")
        .privateKeyPath(Paths.get("/path/to/private.key"))
        .build()
        .generate();
```

#### Generating a JWT with Custom Claims

In some instances, you might want to define custom claims.

##### Kotlin

```kotlin
// Add them individually using addClaim
val jws = Jwt.builder()
    .applicationId("your-application-id")
    .privateKeyPath(Paths.get("/path/to/private.key"))
    .addClaim("foo", "bar")
    .addClaim("bat", "baz")
    .build()
    .generate()

// Or add multiples using a map
val jws = Jwt.builder()
    .applicationId("your-application-id")
    .privateKeyPath(Paths.get("/path/to/private.key"))
    .claims(mapOf("foo" to "bar", "bat" to "baz"))
    .build()
    .generate()
```

##### Java

```java
// Add them individually using addClaim
String jws = Jwt.builder()
        .applicationId("your-application-id")
        .privateKeyPath(Paths.get("/path/to/private.key"))
        .addClaim("foo", "bar")
        .addClaim("bat", "baz")
        .build()
        .generate();

// Or add multiples using a map
String jws = Jwt.builder()
        .applicationId("your-application-id")
        .privateKeyPath(Paths.get("/path/to/private.key"))
        .claims(Map.of("foo", "bar", "bat", "baz"))
        .build()
        .generate();
```
