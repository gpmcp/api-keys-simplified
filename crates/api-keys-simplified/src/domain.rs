use crate::error::ConfigError;
use crate::{
    config::{Environment, KeyConfig, KeyPrefix, Separator},
    error::Result,
    generator::KeyGenerator,
    hasher::KeyHasher,
    secure::SecureString,
    validator::KeyValidator,
    HashConfig,
};
use derive_getters::Getters;
use std::fmt::Debug;

#[derive(Clone, Getters)]
pub struct ApiKeyManager {
    #[getter(skip)]
    generator: KeyGenerator,
    hasher: KeyHasher,
    #[getter(skip)]
    validator: KeyValidator,
}

// FIXME: Need better naming
#[derive(Debug)]
pub struct Hashed(SecureString);
#[derive(Debug)]
pub struct UnHashed;

/// Represents a generated API key with its hash.
///
/// The key field is stored in a `SecureString` which automatically zeros
/// its memory on drop, preventing potential memory disclosure.
pub struct ApiKey<Hash> {
    key: SecureString,
    hash: Hash,
}

// Custom Debug implementation to prevent accidental key logging
impl<T: Debug> Debug for ApiKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("key", &"[REDACTED]")
            .field("hash", &self.hash)
            .finish()
    }
}

impl ApiKeyManager {
    pub fn init(
        prefix: impl Into<String>,
        config: KeyConfig,
        hash_config: HashConfig,
    ) -> std::result::Result<Self, ConfigError> {
        let prefix = KeyPrefix::new(prefix)?;
        let generator = KeyGenerator::new(prefix, config);
        let validator = KeyValidator::new(&hash_config)?;
        let hasher = KeyHasher::new(hash_config);

        Ok(Self {
            generator,
            hasher,
            validator,
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

    pub fn generate(&self, environment: impl Into<Environment>) -> Result<ApiKey<Hashed>> {
        let key = self.generator.generate(environment.into())?;
        let api_key = ApiKey::new(key).into_hashed(&self.hasher)?;

        Ok(api_key)
    }

    pub fn verify(&self, key: &SecureString, stored_hash: impl AsRef<str>) -> Result<bool> {
        self.validator.verify(key.as_ref(), stored_hash.as_ref())
    }

    pub fn verify_checksum(&self, key: &SecureString) -> Result<bool> {
        KeyGenerator::verify_checksum(key.as_ref())
    }
}

impl<T> ApiKey<T> {
    /// Returns a reference to the secure API key.
    ///
    /// To access the underlying string, use `.as_ref()` on the returned `SecureString`:
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManager, Environment};
    /// # let generator = ApiKeyManager::init_default_config("sk").unwrap();
    /// # let api_key = generator.generate(Environment::production()).unwrap();
    /// let key_str: &str = api_key.key().as_ref();
    /// ```
    ///
    /// # Security Note
    ///
    /// The key is stored in secure memory that is automatically zeroed on drop.
    /// Be careful NOT to clone or log the value unnecessarily.
    pub fn key(&self) -> &SecureString {
        &self.key
    }

    /// Returns Prefix and Environment.
    /// Which can be used to early verify if the key matches prefix,
    /// to avoid heavy computation.
    /// And Environment can be used to set different rate limits.
    pub fn parse_key(&self, separator: Separator) -> Result<(String, String)> {
        KeyGenerator::parse_key(self.key.as_ref(), separator)
    }
}

impl ApiKey<UnHashed> {
    pub fn new(key: SecureString) -> ApiKey<UnHashed> {
        ApiKey {
            key,
            hash: UnHashed,
        }
    }
    pub fn into_hashed(self, hasher: &KeyHasher) -> Result<ApiKey<Hashed>> {
        let hash = hasher.hash(&self.key)?;

        Ok(ApiKey {
            key: self.key,
            hash: Hashed(hash),
        })
    }
}

impl ApiKey<Hashed> {
    pub fn hash(&self) -> &SecureString {
        &self.hash.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_lifecycle() {
        let generator = ApiKeyManager::init_default_config("sk").unwrap();
        let api_key = generator.generate(Environment::production()).unwrap();

        let key_str = api_key.key();
        let hash_str = api_key.hash().as_ref();

        assert!(key_str.as_ref().starts_with("sk-live-"));
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
    fn test_parsing() {
        let key = SecureString::from("sk/live/abc123xyz789".to_string());
        let api_key = ApiKey::new(key);
        let (prefix, env) = api_key.parse_key(Separator::Slash).unwrap();

        assert_eq!(prefix, "sk");
        assert_eq!(env, "live");
    }

    #[test]
    fn test_custom_config() {
        let config = KeyConfig::new()
            .with_entropy(32)
            .unwrap()
            .with_checksum(true);

        let generator = ApiKeyManager::init("custom", config, HashConfig::default()).unwrap();
        let key = generator.generate(Environment::production()).unwrap();
        assert!(generator.verify_checksum(key.key()).unwrap());
    }
}
