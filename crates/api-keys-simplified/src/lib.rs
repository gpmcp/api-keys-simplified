//! # API Keys Simplified
//!
//! Secure API key generation and validation with sensible defaults.
//!
//! ## Quick Start
//!
//! ```rust
//! use api_keys_simplified::{ApiKeyGenerator, Environment};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key
//! let generator = ApiKeyGenerator::init_default_config("sk")?;
//! let key = generator.generate(Environment::production())?;
//! println!("Key: {}", key.key().as_ref()); // Show once to user
//! let hash = key.hash(); // Store this in database
//!
//! // Validate a key
//! let is_valid = key.verify(hash)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

mod config;
mod domain;
mod error;
mod generator;
mod hasher;
mod secure;
mod validator;

pub use config::{Environment, HashConfig, KeyConfig, KeyPrefix, Separator};
pub use domain::{ApiKey, ApiKeyGenerator};
pub use error::{Error, Result};
pub use secure::SecureString;
