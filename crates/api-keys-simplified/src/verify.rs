//! # Verify layer (level 2)
//!
//! Everything needed to check a presented key against a stored hash: the
//! [`Verifier`], the [`KeyStatus`] outcome, and [`VerifyError`].
//!
//! Depends only on `config` and `shared`. It never imports `generate`. Checksum
//! validation goes through the shared [`Checksummer`] (the same type the generate
//! layer uses to append), so the two paths share logic without a cross-import.
//!
//! ## Security flow
//! 1. **Checksum** (if enabled): reject malformed keys in ~microseconds.
//! 2. **Hash verify**: dispatched by [`KeyHasher`] on the stored hash's tag
//!    (constant-time; Argon2 is ~hundreds of ms, SHA-256/HMAC are ~microseconds).
//! 3. **Expiry**: reject keys expired beyond the grace period.
//!
//! Timing-oracle protection: a dummy key + dummy hash drive hashing work even on
//! early rejections, so all failure paths take similar time.

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::config::{ChecksumSpec, ValidatedConfig};
use crate::shared::checksum::Checksummer;
use crate::shared::hasher::KeyHasher;
use crate::shared::secure::{ExposeSecret, SecureString};
use crate::shared::token_parser::{parse_token, Parts};
use crate::shared::{MAX_HASH_LENGTH, MAX_KEY_LENGTH};

/// The outcome of verifying a key. A wrong key/hash is `Invalid` (not an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Valid,
    Invalid,
}

/// Structural failures during verification.
///
/// Note: a *wrong* key returns `Ok(KeyStatus::Invalid)`, not an error. Only
/// oversized / genuinely malformed inputs surface here.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("input exceeds maximum allowed length")]
    InputTooLong,

    #[error("key or expiry segment is malformed")]
    MalformedInput,
}

type Result<T> = std::result::Result<T, VerifyError>;

/// Verifies presented keys against stored hashes.
#[derive(Clone)]
pub struct Verifier {
    checksum: Option<ChecksumSpec>,
    grace_period: Duration,
    /// Hasher used to verify stored hashes; dispatches on the stored hash's tag.
    hasher: KeyHasher,
    /// Dummy stored-hash string for timing-attack protection on early-rejection
    /// paths (produced by `hasher` for `dummy_key`).
    dummy_hash: String,
    /// Dummy key that pairs with `dummy_hash`.
    dummy_key: SecureString,
}

impl Verifier {
    /// Build a verifier from validated config plus a dummy key/hash pair
    /// (constructed once by the manager for timing protection).
    pub fn new(config: &ValidatedConfig, dummy_key: SecureString, dummy_hash: &str) -> Self {
        Self {
            checksum: config.checksum(),
            grace_period: config.grace_period(),
            hasher: KeyHasher::new(config.hash().clone()),
            dummy_hash: dummy_hash.to_string(),
            dummy_key,
        }
    }

    fn has_checksum(&self) -> bool {
        self.checksum.is_some()
    }

    /// Full verification: checksum → Argon2 → expiry.
    pub fn verify(&self, key: &SecureString, stored_hash: &str) -> Result<KeyStatus> {
        if self.has_checksum() && self.verify_checksum(key)? == KeyStatus::Invalid {
            return Ok(KeyStatus::Invalid);
        }
        self.verify_hash_and_expiry(key.expose_secret(), stored_hash)
    }

    /// Constant-time checksum check. Performs dummy checksum work on every
    /// failure branch for timing consistency.
    pub fn verify_checksum(&self, key: &SecureString) -> Result<KeyStatus> {
        let checksummer = match self.checksum {
            Some(spec) => Checksummer::new(spec),
            // No checksum configured: nothing to reject on.
            None => return Ok(KeyStatus::Valid),
        };

        let key_bytes = key.expose_secret().as_bytes();
        if key_bytes.len() > MAX_KEY_LENGTH {
            let _ = checksummer.compute(self.dummy_key.expose_secret().as_bytes(), None);
            return Err(VerifyError::InputTooLong);
        }

        let parts = match parse_token(key_bytes, true) {
            Ok((_, parts)) => parts,
            Err(_) => {
                let _ = checksummer.compute(self.dummy_key.expose_secret().as_bytes(), None);
                return Ok(KeyStatus::Invalid);
            }
        };

        let expected = match parts.checksum {
            Some(c) => c,
            None => {
                let _ = checksummer.compute(self.dummy_key.expose_secret().as_bytes(), None);
                return Ok(KeyStatus::Invalid);
            }
        };

        if checksummer.verify_ct(parts.key, parts.expiry_b64, expected) {
            Ok(KeyStatus::Valid)
        } else {
            Ok(KeyStatus::Invalid)
        }
    }

    fn verify_hash_and_expiry(&self, provided_key: &str, stored_hash: &str) -> Result<KeyStatus> {
        if provided_key.len() > MAX_KEY_LENGTH {
            self.dummy_load();
            return Err(VerifyError::InputTooLong);
        }
        if stored_hash.len() > MAX_HASH_LENGTH {
            self.dummy_load();
            return Err(VerifyError::InputTooLong);
        }

        let token_parts = match parse_token(provided_key.as_bytes(), self.has_checksum()) {
            Ok((_, parts)) => parts,
            Err(_) => {
                self.dummy_load();
                return Ok(KeyStatus::Invalid);
            }
        };

        // Verify the key against the stored hash. `KeyHasher::verify` dispatches
        // on the stored hash's tag (sha256$/hmac-sha256$/$argon2id$) and uses a
        // constant-time comparison; a malformed/unknown tag returns false.
        let hash_ok = self.hasher.verify_key(provided_key.as_bytes(), stored_hash);
        let hash_status = if hash_ok {
            KeyStatus::Valid
        } else {
            KeyStatus::Invalid
        };

        // SECURITY: force the expiry check to run regardless of the hash result
        // so the compiler can't short-circuit it into a timing oracle.
        let expiry_status = self.verify_expiry(token_parts)?;

        match (hash_status, expiry_status) {
            (KeyStatus::Valid, KeyStatus::Valid) => Ok(KeyStatus::Valid),
            _ => Ok(KeyStatus::Invalid),
        }
    }

    fn verify_expiry(&self, parts: Parts) -> Result<KeyStatus> {
        let Some(expiry) = parts.expiry_b64 else {
            return Ok(KeyStatus::Valid);
        };

        let decoded = URL_SAFE_NO_PAD
            .decode(expiry)
            .map_err(|_| VerifyError::MalformedInput)?;
        let expiry_timestamp = i64::from_be_bytes(
            decoded
                .try_into()
                .map_err(|_| VerifyError::MalformedInput)?,
        );

        let now = chrono::Utc::now().timestamp();
        let grace = self.grace_period.as_secs() as i64;

        // Once expired beyond the grace window, stays expired even if the clock
        // moves backwards.
        if expiry_timestamp + grace < now {
            Ok(KeyStatus::Invalid)
        } else {
            Ok(KeyStatus::Valid)
        }
    }

    /// Dummy verification to match the timing of a real verify, using the same
    /// configured algorithm against the internal dummy key/hash pair.
    fn dummy_load(&self) {
        let dummy_bytes = self.dummy_key.expose_secret().as_bytes();
        parse_token(dummy_bytes, self.has_checksum()).ok();
        self.hasher.dummy_verify(&self.dummy_key, &self.dummy_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigBuilder, Environment};
    use crate::generate::Generator;
    use crate::shared::hasher::KeyHasher;

    /// Build a manager-like triple (generator, hasher, verifier) for tests
    /// without depending on the manager layer.
    fn parts(cfg: ValidatedConfig) -> (Generator, KeyHasher, Verifier) {
        let generator = Generator::new(cfg.clone());
        let hasher = KeyHasher::new(cfg.hash().clone());
        let dummy_key = generator.raw_key(Environment::Production, None).unwrap();
        let (_id, dummy_hash) = hasher.hash(&dummy_key).unwrap();
        let verifier = Verifier::new(&cfg, dummy_key, &dummy_hash);
        (generator, hasher, verifier)
    }

    #[test]
    fn valid_key_verifies() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap();
        let (generator, hasher, verifier) = parts(cfg);
        let key = generator
            .generate(Environment::Production, None, &hasher)
            .unwrap();
        assert_eq!(
            verifier
                .verify(key.key(), key.expose_hash().hash())
                .unwrap(),
            KeyStatus::Valid
        );
    }

    #[test]
    fn wrong_key_is_invalid_not_error() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap();
        let (generator, hasher, verifier) = parts(cfg);
        let key = generator
            .generate(Environment::Production, None, &hasher)
            .unwrap();
        let wrong = SecureString::from("sk-live-not-the-real-key".to_string());
        assert_eq!(
            verifier.verify(&wrong, key.expose_hash().hash()).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn oversized_key_is_error() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap();
        let (_g, _h, verifier) = parts(cfg);
        let huge = SecureString::from("a".repeat(MAX_KEY_LENGTH + 1));
        assert!(matches!(
            verifier.verify(&huge, "irrelevant"),
            Err(VerifyError::InputTooLong)
        ));
    }

    #[test]
    fn corrupted_checksum_is_invalid() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap();
        let (generator, _h, verifier) = parts(cfg);
        let key = generator.raw_key(Environment::Production, None).unwrap();
        let body = key.expose_secret().rsplit_once('.').unwrap().0;
        let corrupted = SecureString::from(format!("{body}.deadbeefdeadbeef"));
        assert_eq!(
            verifier.verify_checksum(&corrupted).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn expired_key_beyond_grace_is_invalid() {
        use chrono::{Duration as ChronoDuration, Utc};
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .grace_period(Duration::ZERO)
            .build()
            .unwrap();
        let (generator, hasher, verifier) = parts(cfg);
        let past = Utc::now() - ChronoDuration::hours(1);
        let key = generator
            .generate(Environment::Production, Some(past), &hasher)
            .unwrap();
        assert_eq!(
            verifier
                .verify(key.key(), key.expose_hash().hash())
                .unwrap(),
            KeyStatus::Invalid
        );
    }
}
