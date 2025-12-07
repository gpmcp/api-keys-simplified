#![forbid(unsafe_code)]
//! # API Keys Simplified
//!
//! Secure API key generation and validation with sensible defaults.
//!
//! ## Quick Start
//!
//! ```rust
//! use api_keys_simplified::{ApiKeyManager, Environment, ExposeSecret};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key with checksum (enabled by default for DoS protection)
//! let generator = ApiKeyManager::init_default_config("sk")?;
//! let key = generator.generate(Environment::production())?;
//! println!("Key: {}", key.key().expose_secret()); // Show once to user
//! let hash = key.hash(); // Store this in database
//!
//! // Validate a key - checksum is verified first for DoS protection
//! let is_valid = generator.verify(key.key(), hash)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Why Use Checksums?
//!
//! Keys with checksums provide **2900x faster rejection** of invalid keys:
//! - Invalid keys rejected in ~20μs (checksum validation)
//! - Valid keys verified in ~300ms (Argon2 hashing)
//! - **Protects against DoS attacks** via malformed keys
//!
//! The checksum uses BLAKE3 (cryptographic hash) for integrity verification.

mod config;
mod domain;
mod error;
mod generator;
mod hasher;
mod secure;
mod validator;

pub use config::{ChecksumAlgo, Environment, HashConfig, KeyConfig, KeyPrefix, Separator};
pub use domain::{ApiKey, ApiKeyManager, Hash, NoHash};
pub use error::{ConfigError, Error, Result};
pub use secure::{SecureString, SecureStringExt};

// Re-export secrecy traits for convenience
pub use secrecy::ExposeSecret;
