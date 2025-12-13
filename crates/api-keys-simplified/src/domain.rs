use crate::error::InitError;
use crate::validator::KeyStatus;
use crate::{
    config::{Environment, KeyConfig, KeyPrefix},
    error::Result,
    generator::KeyGenerator,
    hasher::KeyHasher,
    secure::SecureString,
    validator::KeyValidator,
    ExposeSecret, HashConfig,
};
use chrono::{DateTime, Utc};
use derive_getters::Getters;
use std::fmt::Debug;

/// ApiKeyManager is storable object
/// used to generate and verify API keys.
/// It contains immutable config data necessary
/// to operate. It does NOT contain ANY sensitive
/// data.
#[derive(Clone, Getters)]
pub struct ApiKeyManagerV0 {
    #[getter(skip)]
    generator: KeyGenerator,
    hasher: KeyHasher,
    #[getter(skip)]
    validator: KeyValidator,
    #[getter(skip)]
    include_checksum: bool,
    #[getter(skip)]
    expiry_grace_period: std::time::Duration,
}

// FIXME: Need better naming
/// Hash can be safely stored as String
/// in memory without having to worry about
/// zeroizing. Hashes are not secrets and are meant to be stored.
#[derive(Debug)]
pub struct Hash(String);
#[derive(Debug)]
pub struct NoHash;

/// Represents a generated API key with its hash.
///
/// The key field is stored in a `SecureString` which automatically zeros
/// its memory on drop, preventing potential memory disclosure.
#[derive(Debug)]
pub struct ApiKey<Hash> {
    key: SecureString,
    hash: Hash,
}

impl ApiKeyManagerV0 {
    pub fn init(
        prefix: impl Into<String>,
        config: KeyConfig,
        hash_config: HashConfig,
        expiry_grace_period: std::time::Duration,
    ) -> std::result::Result<Self, InitError> {
        let include_checksum = *config.checksum_length() != 0;
        let prefix = KeyPrefix::new(prefix)?;
        let generator = KeyGenerator::new(prefix, config)?;
        let hasher = KeyHasher::new(hash_config);

        // Generate dummy key and its hash for timing attack protection
        let dummy_key = generator.dummy_key().clone();
        let dummy_hash = hasher.hash(&dummy_key)?;

        let validator = KeyValidator::new(include_checksum, dummy_key, dummy_hash)?;

        Ok(Self {
            generator,
            hasher,
            validator,
            include_checksum,
            expiry_grace_period,
        })
    }

    pub fn init_default_config(prefix: impl Into<String>) -> std::result::Result<Self, InitError> {
        Self::init(prefix, KeyConfig::default(), HashConfig::default(), std::time::Duration::ZERO)
    }
    pub fn init_high_security_config(
        prefix: impl Into<String>,
    ) -> std::result::Result<Self, InitError> {
        Self::init(
            prefix,
            KeyConfig::high_security(),
            HashConfig::high_security(),
            std::time::Duration::ZERO,
        )
    }

    /// Generates a new API key for the specified environment.
    ///
    /// The generated key includes a checksum (if enabled) for fast DoS protection.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// let key = manager.generate(Environment::production())?;
    /// println!("Key: {}", key.key().expose_secret());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(&self, environment: impl Into<Environment>) -> Result<ApiKey<Hash>> {
        let key = self.generator.generate(environment.into(), None)?;
        let api_key = ApiKey::new(key).into_hashed(&self.hasher)?;

        Ok(api_key)
    }

    /// Generates a new API key with an expiration timestamp.
    ///
    /// The expiration is embedded in the key itself, making it stateless.
    /// Keys are automatically rejected after the expiry time without database lookups.
    ///
    /// # Use Cases
    ///
    /// - Trial keys (7-30 days)
    /// - Temporary partner access
    /// - Time-limited API access
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment};
    /// # use chrono::{Utc, Duration};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// // Create a 7-day trial key
    /// let expiry = Utc::now() + Duration::days(7);
    /// let key = manager.generate_with_expiry(Environment::production(), expiry)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_with_expiry(
        &self,
        environment: impl Into<Environment>,
        expiry: DateTime<Utc>,
    ) -> Result<ApiKey<Hash>> {
        let key = self.generator.generate(environment.into(), Some(expiry))?;
        let api_key = ApiKey::new(key).into_hashed(&self.hasher)?;

        Ok(api_key)
    }

    /// Verifies an API key against a stored hash.
    ///
    /// Returns `KeyStatus` indicating whether the key is valid or invalid.
    ///
    /// # Parameters
    ///
    /// * `key` - The API key to verify
    /// * `stored_hash` - The Argon2 hash stored in your database
    /// * `expiry_grace_period` - Optional grace period duration after expiry.
    ///   - `None`: Skip expiry validation (all keys treated as non-expired)
    ///   - `Some(Duration::ZERO)`: Strict expiry check (no grace period)
    ///   - `Some(duration)`: Key remains valid for `duration` after its expiry time
    ///
    /// The grace period protects against clock skew issues. Once a key expires beyond
    /// the grace period, it stays expired even if the system clock goes backwards.
    ///
    /// # Security Flow
    ///
    /// 1. **Checksum validation** (if enabled): Rejects invalid keys in ~20μs
    /// 2. **Argon2 verification**: Verifies hash for valid checksums (~300ms)
    /// 3. **Expiry check**: Returns `Invalid` if expired beyond grace period
    ///
    /// # Returns
    ///
    /// - `KeyStatus::Valid` - Key is valid and not expired
    /// - `KeyStatus::Invalid` - Key is invalid (wrong key, hash mismatch, checksum failed, or expired)
    ///
    /// # Note on Revocation
    ///
    /// This method does NOT check revocation status. To implement key revocation:
    /// 1. Mark the hash as revoked in your database
    /// 2. Check revocation status before calling this method
    /// 3. Only call `verify()` for non-revoked hashes
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, KeyStatus};
    /// # use std::time::Duration;
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let key = manager.generate(Environment::production()).unwrap();
    /// match manager.verify(key.key(), key.hash())? {
    ///     KeyStatus::Valid => { /* grant access */ },
    ///     KeyStatus::Invalid => { /* reject - wrong key or expired */ },
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn verify(
        &self,
        key: &SecureString,
        stored_hash: impl AsRef<str>,
    ) -> Result<KeyStatus> {
        if self.include_checksum && !self.verify_checksum(key)? {
            return Ok(KeyStatus::Invalid);
        }

        self.validator
            .verify(key.expose_secret(), stored_hash.as_ref(), self.expiry_grace_period)
    }

    pub fn verify_checksum(&self, key: &SecureString) -> Result<bool> {
        self.generator.verify_checksum(key)
    }
}

impl<T> ApiKey<T> {
    /// Returns a reference to the secure API key.
    ///
    /// To access the underlying string, use `.expose_secret()` on the returned `SecureString`:
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret};
    /// # let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let api_key = generator.generate(Environment::production()).unwrap();
    /// let key_str: &str = api_key.key().expose_secret();
    /// ```
    ///
    /// # Security Note
    ///
    /// The key is stored in secure memory that is automatically zeroed on drop.
    /// Be careful NOT to clone or log the value unnecessarily.
    pub fn key(&self) -> &SecureString {
        &self.key
    }
}

impl ApiKey<NoHash> {
    pub fn new(key: SecureString) -> ApiKey<NoHash> {
        ApiKey { key, hash: NoHash }
    }
    pub fn into_hashed(self, hasher: &KeyHasher) -> Result<ApiKey<Hash>> {
        let hash = hasher.hash(&self.key)?;

        Ok(ApiKey {
            key: self.key,
            hash: Hash(hash),
        })
    }
    pub fn into_key(self) -> SecureString {
        self.key
    }
}

impl ApiKey<Hash> {
    /// Returns hash.
    /// SECURITY:
    /// Although it's safe to store hash,
    /// do NOT make unnecessary clones
    /// and avoid logging the hash.
    pub fn hash(&self) -> &str {
        &self.hash.0
    }
    pub fn into_key(self) -> SecureString {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExposeSecret, SecureStringExt};

    #[test]
    fn test_full_lifecycle() {
        let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
        let api_key = generator.generate(Environment::production()).unwrap();

        let key_str = api_key.key();
        let hash_str = api_key.hash();

        assert!(key_str.expose_secret().starts_with("sk-live-"));
        assert!(hash_str.starts_with("$argon2id$"));

        assert_eq!(
            generator.verify(key_str, hash_str).unwrap(),
            KeyStatus::Valid
        );
        let wrong_key = SecureString::from("wrong_key".to_string());
        assert_eq!(
            generator.verify(&wrong_key, hash_str).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn test_different_presets() {
        let balanced_gen = ApiKeyManagerV0::init_default_config("pk").unwrap();
        let balanced = balanced_gen.generate(Environment::test()).unwrap();

        let high_sec_gen = ApiKeyManagerV0::init_high_security_config("sk").unwrap();
        let high_sec = high_sec_gen.generate(Environment::Production).unwrap();

        assert!(!balanced.key().is_empty());
        assert!(high_sec.key().len() > balanced.key().len());
    }

    #[test]
    fn test_custom_config() {
        let config = KeyConfig::new().with_entropy(32).unwrap();

        let generator = ApiKeyManagerV0::init("custom", config, HashConfig::default(), std::time::Duration::ZERO).unwrap();
        let key = generator.generate(Environment::production()).unwrap();
        assert!(generator.verify_checksum(key.key()).unwrap());
    }
}
