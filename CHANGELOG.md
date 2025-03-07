# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [2.0.1] - 2025-02-03
- Bumped `com.auth0:java-jwt` version to 4.5.0

## [2.0.0] - 2024-07-11
- Rewrite in Java
- Underlying library and implementation based on `com.auth0:java-jwt`
- Time-based claims returned as `Instant`

## [1.1.3] - 2024-07-09
- Remove all spaces and tabs when parsing keys

## [1.1.2] - 2024-07-08
- Fix decoding of keys with CRLF characters
- Internal refactoring
- Bumped `jjwt` version to 0.12.6
- Bumped Kotlin version to 2.0.0
- Bumped Jackson runtime dependency version to 2.17.2

## [1.1.1] - 2024-03-08
- Bumped `jjwt` version to 0.12.5
- Bumped Kotlin version to 1.9.22
- Bumped Jackson runtime dependency version to 2.16.1

## [1.1.0] - 2023-10-29
- Added symmetric HS256 signature verification method to `Jwt`
- Added public key decoding to `KeyConverter`
- Bumped `jjwt` version to 0.12.3
- Bumped Kotlin version to 1.9.10
- Bumped Jackson runtime dependency version to 2.15.3

## [1.0.2] - 2022-08-03
- Bumped dependency versions
- Allow unsigned tokens

## [1.0.1] - 2019-08-15
- Mockito is now test scoped as it was originally intended.