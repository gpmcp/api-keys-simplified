#![forbid(unsafe_code)]
//! # API Keys Simplified
//!
//! Secure API key generation and validation with sensible defaults.
//!
//! ## Quick Start
//!
//! ```rust
//! use api_keys_simplified::{ApiKeyManager, ConfigBuilder, Environment, ExposeSecret, KeyStatus};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Describe the key format. All validation happens here, up front, and
//! //    every problem is reported together.
//! let config = ConfigBuilder::new().prefix("sk").build()?;
//!
//! // 2. Build a manager from the validated config.
//! let manager = ApiKeyManager::new(config)?;
//!
//! // 3. Generate a key (checksum enabled by default for DoS protection).
//! let key = manager.generate(Environment::production())?;
//! println!("Key: {}", key.key().expose_secret()); // Show once to the user
//! let hash = key.expose_hash().hash();            // Store this in your database
//!
//! // 4. Verify — checksum is checked first for fast rejection.
//! assert_eq!(manager.verify(key.key(), hash)?, KeyStatus::Valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The crate is organized as a strict, one-directional dependency tree so the
//! `generate` and `verify` paths never import each other:
//!
//! ```text
//! manager            (orchestrator)
//!   ├── generate     ──┐
//!   └── verify       ──┤ both depend only on ↓ (never on each other)
//!         shared  ─────┘  (checksum, hasher, token_parser, secure)
//!           config        (primitives + ConfigBuilder + ValidatedConfig)
//! ```
//!
//! Shared logic (checksum, hashing) lives in `shared`; `generate` uses it to
//! *append*, `verify` uses it to *check*.

mod config;
mod generate;
mod manager;
mod shared;
mod verify;

pub use config::{
    ChecksumAlgo, ChecksumSpec, ConfigBuilder, ConfigError, ConfigErrors, Environment, Argon2Params,
    KeyPrefix, KeyVersion, Separator, ValidatedConfig,
};
pub use generate::{ApiKey, GenerateError, Hash, NoHash};
pub use manager::{ApiKeyManager, InitError};
pub use shared::hasher::{HashError, KeyHasher};
pub use shared::secure::{SecureString, SecureStringExt};
pub use verify::{KeyStatus, VerifyError};

// Re-export secrecy's ExposeSecret trait for convenience.
pub use secrecy::ExposeSecret;
