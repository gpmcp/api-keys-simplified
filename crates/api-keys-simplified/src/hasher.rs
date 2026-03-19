//! Argon2id password hashing and BLAKE3 key ID generation.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2, Params, Version,
};

use crate::{
    config::HashConfig,
    error::{OperationError, Result},
    ExposeSecret, SecureString,
};

#[derive(Clone)]
pub struct KeyHasher {
    config: HashConfig,
}

impl KeyHasher {
    pub fn new(config: HashConfig) -> Self {
        Self { config }
    }

    /// Hashes an API key using Argon2id with a randomly generated salt.
    ///
    /// Returns a tuple containing:
    /// - A stable key ID (deterministic, derived from the key via BLAKE3)
    /// - The Argon2id PHC-formatted hash string (non-deterministic due to random salt)
    ///
    /// The key ID is a 32-character hex string (16 bytes of BLAKE3 hash) that uniquely
    /// identifies the key. It never changes for the same key, making it perfect for:
    /// - Database indexing and lookups
    /// - Key rotation tracking
    /// - Audit logs
    ///
    /// The PHC hash includes:
    /// - Algorithm identifier (argon2id)
    /// - Version
    /// - Parameters (memory cost, time cost, parallelism)
    /// - Salt (base64-encoded, embedded in the hash string)
    /// - Hash output (base64-encoded)
    ///
    /// Each call generates a new random salt, so hashing the same key multiple
    /// times will produce different PHC hashes but the same key ID. To reproduce
    /// the same hash, use `hash_with_phc()` with the original PHC hash string to
    /// extract and reuse the salt.
    ///
    /// # PHC Format
    ///
    /// The returned string follows the PHC format:
    /// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let key = manager.generate(Environment::production()).unwrap();
    /// // Hashing is done automatically when generating keys
    /// // The hash is stored in PHC format in the returned ApiKey
    /// let hash_data = key.expose_hash();
    /// println!("Key ID: {}", hash_data.key_id());  // Stable identifier
    /// println!("Hash: {}", hash_data.hash());      // PHC format with salt
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn hash(&self, key: &SecureString) -> Result<(String, String)> {
        // Generate stable key ID from the key itself using BLAKE3
        let key_id = self.generate_key_id(key);

        // Generate salt using OS cryptographic random source
        let mut salt_bytes = [0u8; 32];
        getrandom::fill(&mut salt_bytes)
            .map_err(|e| OperationError::Hashing(format!("Failed to generate salt: {}", e)))?;

        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        let phc_hash = self.hash_with_salt_string(key, &salt)?;

        Ok((key_id, phc_hash))
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
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret, SecureString};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let key = manager.generate(Environment::production()).unwrap();
    /// // Extract key ID from a provided API key (e.g., from Authorization header)
    /// let provided_key = SecureString::from("sk-live-abc123...".to_string().into_bytes());
    /// let key_id = manager.extract_key_id(&provided_key);
    ///
    /// // Use key_id for database lookup
    /// // let stored_hash = database.get_by_key_id(&key_id)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_key_id(&self, key: &SecureString) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(key.expose_secret());
        let hash = hasher.finalize();

        // Use first 16 bytes (128 bits) for the key ID
        // This provides enough uniqueness while keeping it reasonably short
        // blake3's to_hex() returns 64 hex chars (32 bytes), we take first 32 (16 bytes)
        hash.to_hex()[..32].to_string()
    }

    /// Hashes an API key using Argon2id with a salt extracted from a PHC hash string.
    /// This is useful when you need to regenerate the same hash from the same key,
    /// ensuring deterministic hashing for verification or testing purposes. The salt
    /// is extracted from the provided PHC-formatted hash string.
    ///
    /// Returns a tuple containing:
    /// - A stable key ID (deterministic, same as from `hash()`)
    /// - The Argon2id PHC hash string (matches original due to same salt)
    ///
    /// # Parameters
    ///
    /// * `key` - The API key to hash
    /// * `phc_hash` - An existing PHC-formatted hash string to extract the salt from
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret, SecureString, ApiKey};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let key1 = manager.generate(Environment::production()).unwrap();
    /// // Regenerate the same hash using the salt from the original hash
    /// let key2 = ApiKey::new(SecureString::from(key1.key().expose_secret().to_vec()))
    ///     .into_hashed_with_phc(manager.hasher(), key1.expose_hash().hash())
    ///     .unwrap();
    ///
    /// assert_eq!(key1.expose_hash(), key2.expose_hash());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn hash_with_phc(&self, key: &SecureString, phc_hash: &str) -> Result<(String, String)> {
        // Generate stable key ID (same as in hash() method)
        let key_id = self.generate_key_id(key);

        // Parse the PHC hash to extract the salt
        let parsed = PasswordHash::new(phc_hash)
            .map_err(|e| OperationError::Hashing(format!("Invalid PHC hash: {}", e)))?;

        let salt = parsed
            .salt
            .ok_or_else(|| OperationError::Hashing("PHC hash missing salt".to_string()))?;

        // Convert the Salt to SaltString
        let salt_str = SaltString::from_b64(salt.as_str())
            .map_err(|e| OperationError::Hashing(format!("Invalid salt in PHC hash: {}", e)))?;

        let phc_hash_result = self.hash_with_salt_string(key, &salt_str)?;

        Ok((key_id, phc_hash_result))
    }

    fn hash_with_salt_string(&self, key: &SecureString, salt: &SaltString) -> Result<String> {
        let params = Params::new(
            *self.config.memory_cost(),
            *self.config.time_cost(),
            *self.config.parallelism(),
            None,
        )
        .map_err(|e| OperationError::Hashing(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let hash = argon2
            .hash_password(key.expose_secret(), salt)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        // SECURITY: Hashes are meant to be stored raw
        // We do NOT need to use SecureString here.
        Ok(hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::new_secure_string;

    #[test]
    fn test_hashing() {
        let key = new_secure_string("sk_test_abc123xyz789".to_string());
        let config = HashConfig::default();
        let hasher = KeyHasher::new(config);

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
        let key = new_secure_string("test_key".to_string());

        let balanced_hasher = KeyHasher::new(HashConfig::balanced());
        let (_key_id1, balanced_hash) = balanced_hasher.hash(&key).unwrap();

        let secure_hasher = KeyHasher::new(HashConfig::high_security());
        let (_key_id2, secure_hash) = secure_hasher.hash(&key).unwrap();

        assert!(!balanced_hash.is_empty());
        assert!(!secure_hash.is_empty());
    }

    #[test]
    fn test_hash_with_same_salt() {
        let key = new_secure_string("sk_test_abc123xyz789".to_string());
        let config = HashConfig::default();
        let hasher = KeyHasher::new(config);

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
        let hasher = KeyHasher::new(HashConfig::default());
        let key1 = new_secure_string("sk-live-key1".to_string());
        let key2 = new_secure_string("sk-live-key2".to_string());

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
        let key = new_secure_string("sk-live-test".to_string());
        let hasher = KeyHasher::new(HashConfig::default());

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
