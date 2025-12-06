use crate::{
    config::{Environment, KeyConfig, KeyPrefix, Separator},
    error::Result,
    generator::KeyGenerator,
    hasher::KeyHasher,
    secure::SecureString,
    validator::KeyValidator,
};

/// Represents a generated API key with its hash.
///
/// The key field is stored in a `SecureString` which automatically zeros
/// its memory on drop, preventing potential memory disclosure.
#[derive(Clone)]
pub struct ApiKey {
    key: SecureString,
    hash: String,
}

// Custom Debug implementation to prevent accidental key logging
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("key", &"[REDACTED]")
            .field("hash", &self.hash)
            .finish()
    }
}

impl ApiKey {
    pub fn generate(
        prefix: impl Into<String>,
        environment: impl Into<Environment>,
        config: KeyConfig,
    ) -> Result<Self> {
        let prefix = KeyPrefix::new(prefix)?;

        let key = KeyGenerator::generate(prefix, environment.into(), &config)?;
        let hash = KeyHasher::hash(&key, &config.hash_config)?;

        Ok(Self {
            key: SecureString::from(key),
            hash,
        })
    }

    pub fn generate_default(
        prefix: impl Into<String>,
        environment: impl Into<Environment>,
    ) -> Result<Self> {
        Self::generate(prefix, environment, KeyConfig::default())
    }

    pub fn generate_high_security(
        prefix: impl Into<String>,
        environment: impl Into<Environment>,
    ) -> Result<Self> {
        Self::generate(prefix, environment, KeyConfig::high_security())
    }

    pub fn verify(provided_key: impl AsRef<str>, stored_hash: impl AsRef<str>) -> Result<bool> {
        KeyValidator::verify(provided_key.as_ref(), stored_hash.as_ref())
    }

    pub fn verify_checksum(key: impl AsRef<str>) -> Result<bool> {
        KeyGenerator::verify_checksum(key.as_ref())
    }

    /// Returns a reference to the secure API key.
    ///
    /// To access the underlying string, use `.as_ref()` on the returned `SecureString`:
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKey, Environment};
    /// # let api_key = ApiKey::generate_default("sk", Environment::production()).unwrap();
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

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn parse_prefix(key: &SecureString, separator: Separator) -> Result<String> {
        KeyGenerator::parse_key(key.as_ref(), separator).map(|(prefix, _)| prefix)
    }

    pub fn parse_environment(key: &SecureString, separator: Separator) -> Result<String> {
        KeyGenerator::parse_key(key.as_ref(), separator).map(|(_, env)| env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_lifecycle() {
        let api_key = ApiKey::generate_default("sk", Environment::production()).unwrap();

        let key_str = api_key.key();
        let hash_str = api_key.hash();

        assert!(key_str.as_ref().starts_with("sk.live."));
        assert!(hash_str.starts_with("$argon2id$"));

        assert!(ApiKey::verify(key_str.as_ref(), hash_str).unwrap());
        assert!(!ApiKey::verify("wrong_key", hash_str).unwrap());
    }

    #[test]
    fn test_different_presets() {
        let balanced = ApiKey::generate_default("pk", Environment::test()).unwrap();
        let high_sec = ApiKey::generate_high_security("sk", Environment::Production).unwrap();

        assert!(!balanced.key().is_empty());
        assert!(high_sec.key().len() > balanced.key().len());
    }

    #[test]
    fn test_parsing() {
        let key = SecureString::from("sk/live/abc123xyz789");
        let prefix = ApiKey::parse_prefix(&key, Separator::Slash).unwrap();
        let env = ApiKey::parse_environment(&key, Separator::Slash).unwrap();

        assert_eq!(prefix, "sk");
        assert_eq!(env, "live");
    }

    #[test]
    fn test_custom_config() {
        let config = KeyConfig::new()
            .with_entropy(32)
            .unwrap()
            .with_checksum(true);

        let key = ApiKey::generate("custom", Environment::production(), config).unwrap();
        assert!(ApiKey::verify_checksum(key.key()).unwrap());
    }
}
