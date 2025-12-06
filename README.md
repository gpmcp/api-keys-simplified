# API Keys Simplified

A secure Rust library for generating and validating API keys with built-in security best practices.

[![Crates.io](https://img.shields.io/crates/v/api-keys-simplified.svg)](https://crates.io/crates/api-keys-simplified)
[![Documentation](https://docs.rs/api-keys-simplified/badge.svg)](https://docs.rs/api-keys-simplified)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Features

- **Cryptographically secure** key generation (192-bit entropy)
- **Argon2id hashing** (memory-hard, OWASP recommended)
- **Constant-time verification** (prevents timing attacks)
- **Automatic memory zeroing** (protects sensitive data)

## Quick Example

```rust
use api_keys_simplified::{ApiKey, Environment};

// Generate a new API key
let api_key = ApiKey::generate_default("myapp_sk", Environment::production())?;

// Show to user once (they must save it)
println!("API Key: {}", api_key.key().as_ref());

// Store only the hash
database.save(api_key.hash());

// Later: verify incoming key
if ApiKey::verify(provided_key, stored_hash)? {
    // Key is valid
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
