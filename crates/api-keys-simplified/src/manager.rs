//! # Manager layer (level 3)
//!
//! [`ApiKeyManager`] is the public orchestrator. It owns the validated config and
//! the three collaborators — [`Generator`], [`KeyHasher`], [`Verifier`] — and does
//! nothing but delegate to them. All the real work lives in the layers below;
//! the manager just wires them together and owns the one-time dummy key/hash used
//! for verify-path timing protection.

use chrono::{DateTime, Utc};

use crate::config::{Environment, ValidatedConfig};
use crate::generate::{ApiKey, GenerateError, Generator, Hash};
use crate::shared::hasher::KeyHasher;
use crate::shared::secure::SecureString;
use crate::verify::{KeyStatus, Verifier, VerifyError};

/// Error raised while constructing an [`ApiKeyManager`].
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The dummy key used for timing protection could not be generated.
    #[error(transparent)]
    Generate(#[from] GenerateError),

    /// The dummy key's hash (for timing protection) could not be computed.
    #[error(transparent)]
    Hash(#[from] crate::shared::hasher::HashError),
}

/// Storable, cloneable handle for generating and verifying API keys.
///
/// Holds no secret material. Build one from a [`ValidatedConfig`].
#[derive(Clone)]
pub struct ApiKeyManager {
    generator: Generator,
    hasher: KeyHasher,
    verifier: Verifier,
}

impl ApiKeyManager {
    /// Construct a manager from a validated configuration.
    ///
    /// The only fallible step is minting the internal dummy key + hash used to
    /// keep verification timing flat.
    pub fn new(config: ValidatedConfig) -> Result<Self, InitError> {
        let generator = Generator::new(config.clone());
        let hasher = KeyHasher::new(config.hash().clone());

        // One-time dummy key/hash for timing-attack protection in the verifier.
        let dummy_key = generator.raw_key(Environment::Production, None)?;
        let (_dummy_id, dummy_hash) = hasher.hash(&dummy_key)?;
        let verifier = Verifier::new(&config, dummy_key, &dummy_hash);

        Ok(Self {
            generator,
            hasher,
            verifier,
        })
    }

    /// Generate a new API key for the given environment.
    pub fn generate(
        &self,
        environment: impl Into<Environment>,
    ) -> Result<ApiKey<Hash>, GenerateError> {
        self.generator
            .generate(environment.into(), None, &self.hasher)
    }

    /// Generate a new API key that carries an embedded expiry timestamp.
    pub fn generate_with_expiry(
        &self,
        environment: impl Into<Environment>,
        expiry: DateTime<Utc>,
    ) -> Result<ApiKey<Hash>, GenerateError> {
        self.generator
            .generate(environment.into(), Some(expiry), &self.hasher)
    }

    /// Verify a presented key against a stored hash.
    pub fn verify(
        &self,
        key: &SecureString,
        stored_hash: impl AsRef<str>,
    ) -> Result<KeyStatus, VerifyError> {
        self.verifier.verify(key, stored_hash.as_ref())
    }

    /// Fast checksum-only pre-check (no Argon2). `Valid` when the checksum
    /// matches or when checksums are disabled.
    pub fn verify_checksum(&self, key: &SecureString) -> Result<KeyStatus, VerifyError> {
        self.verifier.verify_checksum(key)
    }

    /// Derive the stable key id for a presented key (for DB lookups).
    pub fn extract_key_id(&self, key: &SecureString) -> String {
        self.hasher.generate_key_id(key)
    }

    /// The internal hasher, exposed for advanced deterministic-rehash workflows.
    pub fn hasher(&self) -> &KeyHasher {
        &self.hasher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigBuilder;
    use crate::generate::ApiKey;
    use crate::shared::secure::{ExposeSecret, SecureStringExt};

    fn manager() -> ApiKeyManager {
        ApiKeyManager::new(ConfigBuilder::new().prefix("sk").build().unwrap()).unwrap()
    }

    #[test]
    fn full_lifecycle() {
        let m = manager();
        let key = m.generate(Environment::production()).unwrap();
        assert!(key.key().expose_secret().starts_with("sk-live-"));
        assert!(key.expose_hash().hash().starts_with("$argon2id$"));
        assert_eq!(
            m.verify(key.key(), key.expose_hash().hash()).unwrap(),
            KeyStatus::Valid
        );
        let wrong = SecureString::from("wrong".to_string());
        assert_eq!(
            m.verify(&wrong, key.expose_hash().hash()).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn high_security_key_is_longer() {
        let balanced = manager().generate(Environment::test()).unwrap();
        let hs = ApiKeyManager::new(ConfigBuilder::high_security().prefix("sk").build().unwrap())
            .unwrap()
            .generate(Environment::production())
            .unwrap();
        assert!(hs.key().len() > balanced.key().len());
    }

    #[test]
    fn key_id_is_stable_and_matches_lookup() {
        let m = manager();
        let key = m.generate(Environment::production()).unwrap();
        let incoming = SecureString::from(key.key().expose_secret());
        assert_eq!(m.extract_key_id(&incoming), *key.expose_hash().key_id());
        assert_eq!(
            m.verify(&incoming, key.expose_hash().hash()).unwrap(),
            KeyStatus::Valid
        );
    }

    #[test]
    fn deterministic_rehash_matches() {
        let m = manager();
        let key = m.generate(Environment::production()).unwrap();
        let rehashed = ApiKey::new(SecureString::from(key.key().expose_secret()))
            .into_hashed_with_phc(m.hasher(), key.expose_hash().hash())
            .unwrap();
        assert_eq!(rehashed.expose_hash(), key.expose_hash());
    }
}
