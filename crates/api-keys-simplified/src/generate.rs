//! # Generate layer (level 2)
//!
//! Everything needed to mint a new API key: the [`Generator`], the typestate
//! [`ApiKey`] (`ApiKey<NoHash>` → `ApiKey<Hash>`), and [`GenerateError`].
//!
//! This layer depends only on `config` and `shared`. It never imports `verify`.
//! Checksums are *appended* here via the shared [`Checksummer`]; the verify layer
//! *checks* them via the same shared type — that is the shared logic both paths
//! use without a cross-import.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use derive_getters::Getters;
use zeroize::Zeroizing;

use crate::config::{Environment, ValidatedConfig};
use crate::shared::checksum::Checksummer;
use crate::shared::hasher::KeyHasher;
use crate::shared::secure::SecureString;
use crate::shared::CHECKSUM_SEPARATOR;

/// Error produced while generating (and hashing) a new key.
///
/// Distinct from the verify path's error type: a caller of `generate` can never
/// receive a "verification" variant and vice versa. Each variant wraps the
/// underlying error verbatim rather than stringifying it.
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error(transparent)]
    Rng(#[from] getrandom::Error),

    #[error(transparent)]
    Encoding(#[from] base64::EncodeSliceError),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Hashing(#[from] crate::shared::hasher::HashError),
}

type Result<T> = std::result::Result<T, GenerateError>;

// ---------------------------------------------------------------------------
// ApiKey typestate
// ---------------------------------------------------------------------------

/// The Argon2 hash (PHC format) plus a stable key identifier.
///
/// - `key_id`: deterministic 32-hex-char BLAKE3-derived id, stable across
///   rehashes — ideal for database indexing.
/// - `hash`: the Argon2id PHC string (changes each hash due to random salt).
#[derive(Debug, Getters, PartialEq, Eq)]
pub struct Hash {
    key_id: String,
    hash: String,
}

/// Typestate marker: an [`ApiKey`] that has not been hashed yet.
#[derive(Debug)]
pub struct NoHash;

/// A generated API key. The secret is held in a [`SecureString`] that zeroes on
/// drop. The type parameter tracks whether a hash has been computed.
#[derive(Debug)]
pub struct ApiKey<H> {
    key: SecureString,
    hash: H,
}

impl<H> ApiKey<H> {
    /// The secret key material. Call `.expose_secret()` to read it.
    pub fn key(&self) -> &SecureString {
        &self.key
    }
}

impl ApiKey<NoHash> {
    pub fn new(key: SecureString) -> ApiKey<NoHash> {
        ApiKey { key, hash: NoHash }
    }

    /// Hash this key with a fresh random salt.
    pub fn into_hashed(self, hasher: &KeyHasher) -> Result<ApiKey<Hash>> {
        let (key_id, hash) = hasher.hash(&self.key)?;
        Ok(ApiKey {
            key: self.key,
            hash: Hash { key_id, hash },
        })
    }

    /// Hash this key reusing the salt embedded in an existing PHC hash string,
    /// producing a deterministic (reproducible) hash. Useful for tests.
    pub fn into_hashed_with_phc(self, hasher: &KeyHasher, phc_hash: &str) -> Result<ApiKey<Hash>> {
        let (key_id, hash) = hasher.hash_with_phc(&self.key, phc_hash)?;
        Ok(ApiKey {
            key: self.key,
            hash: Hash { key_id, hash },
        })
    }

    pub fn into_key(self) -> SecureString {
        self.key
    }
}

impl ApiKey<Hash> {
    /// The hash bundle to store in your database.
    pub fn expose_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn into_key(self) -> SecureString {
        self.key
    }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Mints new API keys according to a [`ValidatedConfig`].
#[derive(Clone)]
pub struct Generator {
    config: ValidatedConfig,
}

impl Generator {
    pub fn new(config: ValidatedConfig) -> Self {
        Self { config }
    }

    fn checksummer(&self) -> Option<Checksummer> {
        self.config.checksum().map(Checksummer::new)
    }

    fn random_entropy(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(vec![0u8; self.config.entropy_bytes()]);
        getrandom::fill(&mut bytes)?;
        Ok(bytes)
    }

    /// Produce a raw key string (no hashing). Also used to build the dummy key
    /// for the verify layer's timing-attack protection.
    pub fn raw_key(
        &self,
        environment: Environment,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<SecureString> {
        let bytes = self.random_entropy()?;

        // Encode entropy directly into a zeroizing buffer (no intermediate String).
        let encoded_len = (4 * bytes.len()).div_ceil(3);
        let mut encoded = Zeroizing::new(vec![0u8; encoded_len]);
        URL_SAFE_NO_PAD.encode_slice(&bytes, &mut encoded)?;

        let sep: &'static str = self.config.separator().into();
        let env: &'static str = environment.into();
        let version_component = self.config.version().component();

        let checksum_length = self
            .config
            .checksum()
            .map(|c| c.length + 1) // +1 for the '.' separator
            .unwrap_or(0);
        let version_length = if version_component.is_empty() {
            0
        } else {
            sep.len() + version_component.len()
        };
        let exp_string = expiry.map(|e| URL_SAFE_NO_PAD.encode(e.timestamp().to_be_bytes()));
        let expiry_length = exp_string.as_ref().map(|b| b.len() + 1).unwrap_or(0);

        let capacity = self.config.prefix().as_str().len()
            + version_length
            + sep.len()
            + env.len()
            + sep.len()
            + encoded.len()
            + expiry_length
            + checksum_length;

        // SECURITY: exact-capacity single buffer, moved into SecureString on
        // success so the sensitive material is zeroed on drop.
        let mut key = Vec::with_capacity(capacity);
        key.extend_from_slice(self.config.prefix().as_str().as_bytes());
        if !version_component.is_empty() {
            key.extend_from_slice(sep.as_bytes());
            key.extend_from_slice(version_component.as_bytes());
        }
        key.extend_from_slice(sep.as_bytes());
        key.extend_from_slice(env.as_bytes());
        key.extend_from_slice(sep.as_bytes());
        key.append(&mut encoded);

        // Checksum is computed over the key body (and expiry, if present) BEFORE
        // the expiry / checksum separators are appended.
        let exp_bytes = exp_string.as_ref().map(|v| v.as_bytes());
        let checksum = self.checksummer().map(|c| c.compute(&key, exp_bytes));

        if let Some(b) = exp_bytes {
            key.push(CHECKSUM_SEPARATOR);
            key.extend_from_slice(b);
        }
        if let Some(checksum) = checksum {
            key.push(CHECKSUM_SEPARATOR);
            key.append(&mut checksum.into_bytes());
        }

        let key = String::from_utf8(key)?;
        Ok(SecureString::from(key))
    }

    /// Mint and hash a new key.
    pub fn generate(
        &self,
        environment: Environment,
        expiry: Option<DateTime<Utc>>,
        hasher: &KeyHasher,
    ) -> Result<ApiKey<Hash>> {
        let key = self.raw_key(environment, expiry)?;
        ApiKey::new(key).into_hashed(hasher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigBuilder, KeyVersion, Separator};
    use crate::shared::secure::ExposeSecret;

    fn generator(cfg: ValidatedConfig) -> Generator {
        Generator::new(cfg)
    }

    #[test]
    fn generates_prefixed_key_with_checksum() {
        let cfg = ConfigBuilder::new().prefix("sk").build().unwrap();
        let g = generator(cfg);
        let key = g.raw_key(Environment::Production, None).unwrap();
        let s = key.expose_secret();
        assert!(s.starts_with("sk-live-"));
        assert_eq!(s.matches('.').count(), 1, "one dot for checksum: {s}");
    }

    #[test]
    fn version_component_is_embedded() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .version(KeyVersion::V1)
            .build()
            .unwrap();
        let key = generator(cfg).raw_key(Environment::Test, None).unwrap();
        assert!(key.expose_secret().starts_with("sk-v1-test-"));
    }

    #[test]
    fn no_checksum_has_no_dot() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .no_checksum()
            .build()
            .unwrap();
        let key = generator(cfg)
            .raw_key(Environment::Production, None)
            .unwrap();
        assert!(!key.expose_secret().contains('.'));
    }

    #[test]
    fn separator_is_honored() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .separator(Separator::Slash)
            .build()
            .unwrap();
        let key = generator(cfg)
            .raw_key(Environment::Production, None)
            .unwrap();
        assert!(key.expose_secret().contains('/'));
    }

    #[test]
    fn underscore_separator_produces_stripe_style_key() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .separator(Separator::Underscore)
            .build()
            .unwrap();
        let key = generator(cfg)
            .raw_key(Environment::Production, None)
            .unwrap();
        // e.g. "sk_live_<base64>.<checksum>"
        assert!(key.expose_secret().starts_with("sk_live_"));
        // Exactly one '.', for the checksum delimiter (never for the separator).
        assert_eq!(key.expose_secret().matches('.').count(), 1);
    }

    #[test]
    fn higher_entropy_yields_longer_key() {
        use crate::shared::secure::SecureStringExt;
        let small = ConfigBuilder::new()
            .prefix("sk")
            .entropy(16)
            .build()
            .unwrap();
        let big = ConfigBuilder::new()
            .prefix("sk")
            .entropy(48)
            .build()
            .unwrap();
        let k1 = generator(small)
            .raw_key(Environment::Development, None)
            .unwrap();
        let k2 = generator(big)
            .raw_key(Environment::Development, None)
            .unwrap();
        assert!(k2.len() > k1.len());
    }
}
