use crate::error::ConfigError;
use crate::{
    config::{Environment, KeyConfig, KeyPrefix},
    error::Result,
    generator::KeyGenerator,
    hasher::KeyHasher,
    secure::SecureString,
    validator::KeyValidator,
    ExposeSecret, HashConfig,
};
use derive_getters::Getters;
use std::fmt::Debug;

/// ApiKeyManager is storable object
/// used to generate and verify API keys.
/// It contains immutable config data necessary
/// to operate. It does NOT contain ANY sensitive
/// data.
#[derive(Clone, Getters)]
pub struct ApiKeyManager {
    #[getter(skip)]
    generator: KeyGenerator,
    hasher: KeyHasher,
    #[getter(skip)]
    validator: KeyValidator,
    #[getter(skip)]
    include_checksum: bool,
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

impl ApiKeyManager {
    pub fn init(
        prefix: impl Into<String>,
        config: KeyConfig,
        hash_config: HashConfig,
    ) -> std::result::Result<Self, ConfigError> {
        let include_checksum = *config.checksum_length() != 0;
        let prefix = KeyPrefix::new(prefix)?;
        let generator = KeyGenerator::new(prefix, config);
        let validator = KeyValidator::new(&hash_config)?;
        let hasher = KeyHasher::new(hash_config);

        Ok(Self {
            generator,
            hasher,
            validator,
            include_checksum,
        })
    }

    pub fn init_default_config(
        prefix: impl Into<String>,
    ) -> std::result::Result<Self, ConfigError> {
        Self::init(prefix, KeyConfig::default(), HashConfig::default())
    }
    pub fn init_high_security_config(
        prefix: impl Into<String>,
    ) -> std::result::Result<Self, ConfigError> {
        Self::init(
            prefix,
            KeyConfig::high_security(),
            HashConfig::high_security(),
        )
    }

    pub fn generate(&self, environment: impl Into<Environment>) -> Result<ApiKey<Hash>> {
        let key = self.generator.generate(environment.into())?;
        let api_key = ApiKey::new(key).into_hashed(&self.hasher)?;

        Ok(api_key)
    }

    pub fn verify(&self, key: &SecureString, stored_hash: impl AsRef<str>) -> Result<bool> {
        if self.include_checksum && !self.verify_checksum(key)? {
            return Ok(false);
        }

        self.validator
            .verify(key.expose_secret(), stored_hash.as_ref())
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
    /// # use api_keys_simplified::{ApiKeyManager, Environment, ExposeSecret};
    /// # let generator = ApiKeyManager::init_default_config("sk").unwrap();
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
        let generator = ApiKeyManager::init_default_config("sk").unwrap();
        let api_key = generator.generate(Environment::production()).unwrap();

        let key_str = api_key.key();
        let hash_str = api_key.hash();

        assert!(key_str.expose_secret().starts_with("sk-live-"));
        assert!(hash_str.starts_with("$argon2id$"));

        assert!(generator.verify(key_str, hash_str).unwrap());
        let wrong_key = SecureString::from("wrong_key".to_string());
        assert!(!generator.verify(&wrong_key, hash_str).unwrap());
    }

    #[test]
    fn test_different_presets() {
        let balanced_gen = ApiKeyManager::init_default_config("pk").unwrap();
        let balanced = balanced_gen.generate(Environment::test()).unwrap();

        let high_sec_gen = ApiKeyManager::init_high_security_config("sk").unwrap();
        let high_sec = high_sec_gen.generate(Environment::Production).unwrap();

        assert!(!balanced.key().is_empty());
        assert!(high_sec.key().len() > balanced.key().len());
    }

    #[test]
    fn test_custom_config() {
        let config = KeyConfig::new().with_entropy(32).unwrap();

        let generator = ApiKeyManager::init("custom", config, HashConfig::default()).unwrap();
        let key = generator.generate(Environment::production()).unwrap();
        assert!(generator.verify_checksum(key.key()).unwrap());
    }
}
