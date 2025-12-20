# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/gpmcp/api-keys-simplified/compare/v0.3.0...v0.4.0) - 2025-12-20

### Fixed

- expose salt used for hash ([#22](https://github.com/gpmcp/api-keys-simplified/pull/22))

## [0.3.0](https://github.com/gpmcp/api-keys-simplified/compare/v0.2.1...v0.3.0) - 2025-12-13

### Fixed

- key expiration logic ([#20](https://github.com/gpmcp/api-keys-simplified/pull/20))

## [0.2.1](https://github.com/gpmcp/api-keys-simplified/compare/v0.2.0...v0.2.1) - 2025-12-11

### Other

- update examples with v0 manager and secure string types

## [0.2.0](https://github.com/gpmcp/api-keys-simplified/compare/v0.1.1...v0.2.0) - 2025-12-09

### Added

- add ApiKeyGenerator wrapper
- add comprehensive key versioning
- ability to add expiry for keys
- allow `-` in prefix
- 

### Fixed

- key prefix validation tests
- prevent timing oracle in expiry verification
- oracle vulnr while verification
- key prefix validation tests

## [0.1.1](https://github.com/gpmcp/api-keys-simplified/compare/v0.1.0...v0.1.1) - 2025-12-06

### Added

- Add codecov badge in readme and Add docs for Environment
