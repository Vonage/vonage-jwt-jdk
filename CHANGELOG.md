# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [1.1.0] - 2023-10-27
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