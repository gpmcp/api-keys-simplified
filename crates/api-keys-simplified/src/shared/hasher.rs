use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{Argon2Params, HashAlgo};
use crate::shared::secure::{ExposeSecret, SecureString};

type HmacSha256 = Hmac<Sha256>;

/// Error produced by the shared hashing primitive.
///
/// Lives in the shared layer because both the generate and verify paths hash.
/// Each variant wraps the underlying error verbatim rather than stringifying it.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Secure RNG failure while generating an Argon2 salt.
    #[error(transparent)]
    Rng(#[from] getrandom::Error),

    /// PHC / salt / password-hashing failure (argon2's `password_hash` layer).
    #[error(transparent)]
    PasswordHash(#[from] argon2::password_hash::Error),

    /// Invalid Argon2 parameters.
    #[error(transparent)]
    Argon2(#[from] argon2::Error),

    /// The HMAC key (pepper) had an invalid length.
    #[error(transparent)]
    HmacKey(#[from] hmac::digest::InvalidLength),

    /// The supplied PHC hash string had no salt to reuse.
    #[error("PHC hash missing salt")]
    MissingSalt,
}

type Result<T> = std::result::Result<T, HashError>;

/// Hashes and verifies keys according to a configured [`HashAlgo`].
///
/// The stored-hash string is **self-describing**: each algorithm produces a
/// tagged string (`$argon2id$…`, `sha256$<hex>`, `hmac-sha256$<hex>`) so
/// [`KeyHasher::verify`] can dispatch on the stored value's prefix without any
/// external "which algorithm" state. This lets a database hold hashes from
/// multiple algorithms (e.g. during a migration) and still verify correctly.
#[derive(Clone)]
pub struct KeyHasher {
    algo: HashAlgo,
}

impl KeyHasher {
    pub fn new(algo: HashAlgo) -> Self {
        Self { algo }
    }

    /// Hashes an API key with the configured algorithm.
    ///
    /// Returns a tuple containing:
    /// - A stable key ID (deterministic BLAKE3-derived id, independent of the
    ///   hash algorithm — see [`KeyHasher::generate_key_id`]).
    /// - The self-describing, tagged stored-hash string to persist:
    ///   - `HashAlgo::Sha256`      → `sha256$<hex64>`
    ///   - `HashAlgo::HmacSha256`  → `hmac-sha256$<hex64>`
    ///   - `HashAlgo::Argon2id`    → native PHC `$argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>`
    ///
    /// SHA-256 and HMAC-SHA256 are deterministic (no salt); Argon2id embeds a
    /// fresh random salt so its output differs each call while the key ID stays
    /// constant.
    pub fn hash(&self, key: &SecureString) -> Result<(String, String)> {
        let key_id = self.generate_key_id(key);
        let key_bytes = key.expose_secret().as_bytes();

        let stored = match &self.algo {
            HashAlgo::Sha256 => format!("sha256${}", hex_sha256(key_bytes)),
            HashAlgo::HmacSha256 { pepper } => {
                format!("hmac-sha256${}", hex_hmac(pepper, key_bytes)?)
            }
            HashAlgo::Argon2id(params) => {
                // Random salt from the OS CSPRNG, embedded in the PHC string.
                let mut salt_bytes = [0u8; 32];
                getrandom::fill(&mut salt_bytes)?;
                let salt = SaltString::encode_b64(&salt_bytes)?;
                argon2_hash(params, key, &salt)?
            }
        };

        Ok((key_id, stored))
    }

    /// Generates a stable, deterministic key ID from an API key.
    ///
    /// Uses BLAKE3 hash (truncated to 16 bytes) to create a unique identifier
    /// that never changes for the same key. This is useful for:
    /// - Database primary keys or indexes
    /// - Key lookup without exposing the key itself
    /// - Tracking key usage across hash rotations
    ///
    /// # Format
    ///
    /// Returns a 32-character hex string (16 bytes / 128 bits).
    ///
    /// # Security Note
    ///
    /// While this is a one-way hash, it should still be treated as sensitive
    /// data since it uniquely identifies a key. Don't expose it in public APIs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # use api_keys_simplified::{ApiKeyManager, ConfigBuilder, Environment, ExposeSecret, SecureString};
    /// # let manager = ApiKeyManager::new(ConfigBuilder::new().prefix("sk").build().unwrap()).unwrap();
    /// # let key = manager.generate(Environment::production()).unwrap();
    /// // Extract key ID from a provided API key (e.g., from Authorization header)
    /// let provided_key = SecureString::from("sk-live-abc123...".to_string());
    /// let key_id = manager.extract_key_id(&provided_key);
    ///
    /// // Use key_id for database lookup
    /// // let stored_hash = database.get_by_key_id(&key_id)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_key_id(&self, key: &SecureString) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(key.expose_secret().as_bytes());
        let hash = hasher.finalize();

        // Use first 16 bytes (128 bits) for the key ID
        // This provides enough uniqueness while keeping it reasonably short
        // blake3's to_hex() returns 64 hex chars (32 bytes), we take first 32 (16 bytes)
        hash.to_hex()[..32].to_string()
    }

    /// Deterministically reproduces a stored hash for the same key.
    ///
    /// - For `Sha256` / `HmacSha256`, hashing is already deterministic, so the
    ///   `existing` argument is ignored and the same string is recomputed.
    /// - For `Argon2id`, the salt is extracted from the provided PHC string and
    ///   reused so the output matches the original.
    ///
    /// Useful for tests and hash-consistency checks.
    pub fn hash_with_phc(&self, key: &SecureString, existing: &str) -> Result<(String, String)> {
        let key_id = self.generate_key_id(key);
        let key_bytes = key.expose_secret().as_bytes();

        let stored = match &self.algo {
            HashAlgo::Sha256 => format!("sha256${}", hex_sha256(key_bytes)),
            HashAlgo::HmacSha256 { pepper } => {
                format!("hmac-sha256${}", hex_hmac(pepper, key_bytes)?)
            }
            HashAlgo::Argon2id(params) => {
                let parsed = PasswordHash::new(existing)?;
                let salt = parsed.salt.ok_or(HashError::MissingSalt)?;
                let salt_str = SaltString::from_b64(salt.as_str())?;
                argon2_hash(params, key, &salt_str)?
            }
        };

        Ok((key_id, stored))
    }

    /// Verifies a key against a stored hash string.
    ///
    /// Dispatches on the stored string's tag/prefix, **not** on the configured
    /// algorithm, so a database containing hashes from multiple algorithms
    /// verifies correctly (e.g. during a migration). The only role the configured
    /// algorithm plays is supplying the HMAC pepper when the stored hash is an
    /// `hmac-sha256$` value.
    ///
    /// Uses constant-time comparison for the digest algorithms; Argon2's verifier
    /// is constant-time internally.
    pub(crate) fn verify_key(&self, key_bytes: &[u8], stored_hash: &str) -> bool {
        if let Some(hex) = stored_hash.strip_prefix("sha256$") {
            let computed = hex_sha256(key_bytes);
            return ct_eq_str(&computed, hex);
        }

        if let Some(hex) = stored_hash.strip_prefix("hmac-sha256$") {
            // Requires the configured pepper; without it we cannot verify.
            let HashAlgo::HmacSha256 { pepper } = &self.algo else {
                return false;
            };
            let Ok(computed) = hex_hmac(pepper, key_bytes) else {
                return false;
            };
            return ct_eq_str(&computed, hex);
        }

        if stored_hash.starts_with("$argon2id$") {
            return match PasswordHash::new(stored_hash) {
                Ok(parsed) => Argon2::default()
                    .verify_password(key_bytes, &parsed)
                    .is_ok(),
                Err(_) => false,
            };
        }

        // Unknown/malformed stored-hash tag.
        false
    }

    /// Convenience wrapper over [`KeyHasher::verify_key`] taking a [`SecureString`].
    pub(crate) fn verify(&self, key: &SecureString, stored_hash: &str) -> bool {
        self.verify_key(key.expose_secret().as_bytes(), stored_hash)
    }

    /// Performs dummy hashing/verification work matching the configured algorithm
    /// so early-rejection paths take similar time to a real verification.
    pub(crate) fn dummy_verify(&self, dummy_key: &SecureString, dummy_hash: &str) {
        let _ = self.verify(dummy_key, dummy_hash);
    }
}

// ---------------------------------------------------------------------------
// Free helpers (algorithm implementations)
// ---------------------------------------------------------------------------

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn hex_hmac(pepper: &SecureString, bytes: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(pepper.expose_secret().as_bytes())?;
    mac.update(bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn argon2_hash(params: &Argon2Params, key: &SecureString, salt: &SaltString) -> Result<String> {
    let p = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        None,
    )?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, p);
    let hash = argon2.hash_password(key.expose_secret().as_bytes(), salt)?;

    // SECURITY: hashes are meant to be stored raw; no SecureString needed.
    Ok(hash.to_string())
}

/// Constant-time equality of two hex strings (as byte slices).
fn ct_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argon() -> KeyHasher {
        KeyHasher::new(HashAlgo::Argon2id(Argon2Params::balanced()))
    }

    #[test]
    fn test_hashing() {
        let key = SecureString::from("sk_test_abc123xyz789".to_string());
        let hasher = argon();

        let (key_id1, hash1) = hasher.hash(&key).unwrap();
        let (key_id2, hash2) = hasher.hash(&key).unwrap();

        // Key IDs should be the same (derived from the key)
        assert_eq!(key_id1, key_id2);
        // Hashes should be different (different salts embedded in PHC format)
        assert_ne!(hash1, hash2);
        assert!(hash1.starts_with("$argon2id$"));
        assert!(hash2.starts_with("$argon2id$"));
    }

    #[test]
    fn test_different_configs() {
        let key = SecureString::from("test_key".to_string());

        let balanced_hasher = KeyHasher::new(HashAlgo::Argon2id(Argon2Params::balanced()));
        let (_key_id1, balanced_hash) = balanced_hasher.hash(&key).unwrap();

        let secure_hasher = KeyHasher::new(HashAlgo::Argon2id(Argon2Params::high_security()));
        let (_key_id2, secure_hash) = secure_hasher.hash(&key).unwrap();

        assert!(!balanced_hash.is_empty());
        assert!(!secure_hash.is_empty());
    }

    // -- New-algorithm coverage -------------------------------------------

    #[test]
    fn sha256_is_tagged_deterministic_and_verifies() {
        let key = SecureString::from("sk-live-abc".to_string());
        let hasher = KeyHasher::new(HashAlgo::Sha256);
        let (id1, h1) = hasher.hash(&key).unwrap();
        let (id2, h2) = hasher.hash(&key).unwrap();

        assert!(h1.starts_with("sha256$"));
        assert_eq!(h1, h2, "sha256 is deterministic");
        assert_eq!(id1, id2);
        assert_eq!(h1.strip_prefix("sha256$").unwrap().len(), 64); // 32-byte hex
        assert!(hasher.verify(&key, &h1));
        assert!(!hasher.verify(&SecureString::from("wrong".to_string()), &h1));
    }

    #[test]
    fn hmac_sha256_is_keyed_and_verifies() {
        let pepper = SecureString::from("server-pepper".to_string());
        let hasher = KeyHasher::new(HashAlgo::HmacSha256 {
            pepper: pepper.clone(),
        });
        let key = SecureString::from("sk-live-abc".to_string());
        let (_id, h) = hasher.hash(&key).unwrap();

        assert!(h.starts_with("hmac-sha256$"));
        assert!(hasher.verify(&key, &h));

        // A different pepper must NOT verify the same stored hash.
        let other = KeyHasher::new(HashAlgo::HmacSha256 {
            pepper: SecureString::from("different-pepper".to_string()),
        });
        assert!(!other.verify(&key, &h));

        // Plain sha256 differs from hmac for the same input.
        let sha = KeyHasher::new(HashAlgo::Sha256);
        let (_i, sh) = sha.hash(&key).unwrap();
        assert_ne!(sh.strip_prefix("sha256$"), h.strip_prefix("hmac-sha256$"));
    }

    #[test]
    fn verify_dispatches_on_stored_prefix_not_config() {
        // The self-describing format means verification dispatches on the STORED
        // hash's tag, independent of the configured algo. This is what enables
        // mixed-algo databases during a migration: any configured (unkeyed)
        // hasher verifies another unkeyed algo's stored hash for the same key.
        let key = SecureString::from("sk-live-abc".to_string());
        let sha = KeyHasher::new(HashAlgo::Sha256);
        let argon = argon();

        let (_i, sha_hash) = sha.hash(&key).unwrap();
        let (_j, argon_hash) = argon.hash(&key).unwrap();

        // Cross-config verification of unkeyed hashes SUCCEEDS (by design).
        assert!(argon.verify(&key, &sha_hash));
        assert!(sha.verify(&key, &argon_hash));

        // But the wrong key still fails, whichever config is used.
        let wrong = SecureString::from("nope".to_string());
        assert!(!argon.verify(&wrong, &sha_hash));
        assert!(!sha.verify(&wrong, &argon_hash));
    }

    #[test]
    fn malformed_and_keyed_without_pepper_are_rejected() {
        let key = SecureString::from("sk-live-abc".to_string());
        let sha = KeyHasher::new(HashAlgo::Sha256);

        // Untagged / unknown stored hash -> rejected, no panic.
        assert!(!sha.verify(&key, "garbage-no-tag"));
        assert!(!sha.verify(&key, "md5$deadbeef"));

        // An hmac-sha256$ stored hash cannot be verified by a hasher that has no
        // pepper (e.g. a Sha256-configured verifier) -> rejected.
        let hmac = KeyHasher::new(HashAlgo::HmacSha256 {
            pepper: SecureString::from("p".to_string()),
        });
        let (_i, hmac_hash) = hmac.hash(&key).unwrap();
        assert!(!sha.verify(&key, &hmac_hash));
    }

    #[test]
    fn key_id_is_identical_across_algorithms() {
        let key = SecureString::from("sk-live-abc".to_string());
        let sha = KeyHasher::new(HashAlgo::Sha256);
        let hmac = KeyHasher::new(HashAlgo::HmacSha256 {
            pepper: SecureString::from("p".to_string()),
        });
        let argon = argon();

        let a = sha.generate_key_id(&key);
        let b = hmac.generate_key_id(&key);
        let c = argon.generate_key_id(&key);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn test_hash_with_same_salt() {
        let key = SecureString::from("sk_test_abc123xyz789".to_string());
        let hasher = argon();

        // Get a PHC hash from the first hash
        let (key_id_original, phc_hash) = hasher.hash(&key).unwrap();

        // Use the same salt (extracted from PHC) to generate two hashes
        let (key_id1, hash1) = hasher.hash_with_phc(&key, &phc_hash).unwrap();
        let (key_id2, hash2) = hasher.hash_with_phc(&key, &phc_hash).unwrap();

        // All key IDs should match (derived from same key)
        assert_eq!(key_id1, key_id2);
        assert_eq!(key_id1, key_id_original);
        // Hashes should match (same salt from PHC)
        assert_eq!(hash1, hash2);
        assert_eq!(hash1, phc_hash); // Should match original hash
        assert!(hash1.starts_with("$argon2id$"));
    }

    #[test]
    fn test_key_id_properties() {
        let hasher = argon();
        let key1 = SecureString::from("sk-live-key1".to_string());
        let key2 = SecureString::from("sk-live-key2".to_string());

        // Determinism: same key always produces same ID
        let id1a = hasher.generate_key_id(&key1);
        let id1b = hasher.generate_key_id(&key1);
        assert_eq!(id1a, id1b);

        // Format: 32 hex characters
        assert_eq!(id1a.len(), 32);
        assert!(id1a.chars().all(|c| c.is_ascii_hexdigit()));

        // Uniqueness: different keys produce different IDs
        let id2 = hasher.generate_key_id(&key2);
        assert_ne!(id1a, id2);
    }

    #[test]
    fn test_key_id_stability_with_hashing() {
        let key = SecureString::from("sk-live-test".to_string());
        let hasher = argon();

        let (key_id1, hash1) = hasher.hash(&key).unwrap();
        let (key_id2, hash2) = hasher.hash(&key).unwrap();

        // Key ID stays the same
        assert_eq!(key_id1, key_id2);
        // But hashes differ (different salts)
        assert_ne!(hash1, hash2);

        // hash_with_phc produces matching key ID
        let (key_id3, _) = hasher.hash_with_phc(&key, &hash1).unwrap();
        assert_eq!(key_id1, key_id3);
    }
}
