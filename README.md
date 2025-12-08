# API Keys Simplified

A secure Rust library for generating and validating API keys with built-in security best practices.

[![Crates.io](https://img.shields.io/crates/v/api-keys-simplified.svg)](https://crates.io/crates/api-keys-simplified)
[![Documentation](https://docs.rs/api-keys-simplified/badge.svg)](https://docs.rs/api-keys-simplified)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/gpmcp/api-keys-simplified/graph/badge.svg?token=BUE7WRJ1FP)](https://codecov.io/gh/gpmcp/api-keys-simplified)

## Features

- **Cryptographically secure** key generation (192-bit entropy)
- **Argon2id hashing** (memory-hard, OWASP recommended)
- **BLAKE3 checksums** (2900x faster DoS protection)
- **Constant-time verification** (prevents timing attacks)
- **Automatic memory zeroing** (protects sensitive data)
- **Key expiration** (time-based access control)
- **Key revocation** (instant access denial via stored hash)

## Quick Example

```rust
use api_keys_simplified::{ApiKeyManager, Environment, KeyConfig, HashConfig};

// Generate with checksum (enabled by default - 2900x faster DoS protection)
let manager = ApiKeyManager::init_default_config("myapp_sk")?;
let api_key = manager.generate(Environment::production())?;

// Show to user once (they must save it)
println!("API Key: {}", api_key.key().expose_secret());

// Store only the hash
database.save(api_key.hash());

// Later: verify incoming key (checksum checked first)
let status = manager.verify(provided_key, stored_hash)?;
match status {
    KeyStatus::Valid => { /* grant access */ },
    KeyStatus::Invalid => { /* reject - wrong key */ },
}
```

## Documentation

For complete documentation, see the [library README](crates/api-keys-simplified/README.md) or visit [docs.rs](https://docs.rs/api-keys-simplified).

## Installation

```toml
[dependencies]
api-keys-simplified = "0.1"
```

## Project Structure

```
api-keys-simplified/
├── crates/
│   └── api-keys-simplified/    # Main library crate
└── Cargo.toml                  # Workspace configuration
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## Security

Report vulnerabilities to: [sandip@ssdd.dev](mailto:sandip@ssdd.dev)
