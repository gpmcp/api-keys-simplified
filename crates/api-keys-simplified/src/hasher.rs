use argon2::{
    password_hash::{PasswordHasher, SaltString},
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
    /// Returns the Argon2id PHC-formatted hash string which includes:
    /// - Algorithm identifier (argon2id)
    /// - Version
    /// - Parameters (memory cost, time cost, parallelism)
    /// - Salt (base64-encoded, embedded in the hash string)
    /// - Hash output (base64-encoded)
    ///
    /// Each call generates a new random salt, so hashing the same key multiple
    /// times will produce different hashes. To reproduce the same hash, use
    /// `hash_with_phc()` with the original PHC hash string to extract and reuse the salt.
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
    /// let hash = key.expose_hash();
    /// println!("Hash: {}", hash.hash());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn hash(&self, key: &SecureString) -> Result<String> {
        // Generate salt using OS cryptographic random source
        let mut salt_bytes = [0u8; 32];
        getrandom::fill(&mut salt_bytes)
            .map_err(|e| OperationError::Hashing(format!("Failed to generate salt: {}", e)))?;

        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        self.hash_with_salt_string(key, &salt)
    }

    /// Hashes an API key using Argon2id with a salt extracted from a PHC hash string.
    ///
    /// This is useful when you need to regenerate the same hash from the same key,
    /// ensuring deterministic hashing for verification or testing purposes. The salt
    /// is extracted from the provided PHC-formatted hash string.
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
    /// let key2 = ApiKey::new(SecureString::from(key1.key().expose_secret()))
    ///     .into_hashed_with_phc(manager.hasher(), key1.expose_hash().hash())
    ///     .unwrap();
    ///
    /// assert_eq!(key1.expose_hash(), key2.expose_hash());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn hash_with_phc(&self, key: &SecureString, phc_hash: &str) -> Result<String> {
        use argon2::password_hash::PasswordHash;

        // Parse the PHC hash to extract the salt
        let parsed = PasswordHash::new(phc_hash)
            .map_err(|e| OperationError::Hashing(format!("Invalid PHC hash: {}", e)))?;

        let salt = parsed
            .salt
            .ok_or_else(|| OperationError::Hashing("PHC hash missing salt".to_string()))?;

        // Convert the Salt to SaltString
        let salt_str = SaltString::from_b64(salt.as_str())
            .map_err(|e| OperationError::Hashing(format!("Invalid salt in PHC hash: {}", e)))?;

        self.hash_with_salt_string(key, &salt_str)
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
            .hash_password(key.expose_secret().as_bytes(), salt)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        // SECURITY: Hashes are meant to be stored raw
        // We do NOT need to use SecureString here.
        Ok(hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashing() {
        let key = SecureString::from("sk_test_abc123xyz789".to_string());
        let config = HashConfig::default();
        let hasher = KeyHasher::new(config);

        let hash1 = hasher.hash(&key).unwrap();
        let hash2 = hasher.hash(&key).unwrap();

        assert_ne!(hash1, hash2); // Different salts embedded in PHC format
        assert!(hash1.starts_with("$argon2id$"));
        assert!(hash2.starts_with("$argon2id$"));
    }

    #[test]
    fn test_different_configs() {
        let key = SecureString::from("test_key".to_string());

        let balanced_hasher = KeyHasher::new(HashConfig::balanced());
        let balanced_hash = balanced_hasher.hash(&key).unwrap();

        let secure_hasher = KeyHasher::new(HashConfig::high_security());
        let secure_hash = secure_hasher.hash(&key).unwrap();

        assert!(!balanced_hash.is_empty());
        assert!(!secure_hash.is_empty());
    }

    #[test]
    fn test_hash_with_same_salt() {
        let key = SecureString::from("sk_test_abc123xyz789".to_string());
        let config = HashConfig::default();
        let hasher = KeyHasher::new(config);

        // Get a PHC hash from the first hash
        let phc_hash = hasher.hash(&key).unwrap();

        // Use the same salt (extracted from PHC) to generate two hashes
        let hash1 = hasher.hash_with_phc(&key, &phc_hash).unwrap();
        let hash2 = hasher.hash_with_phc(&key, &phc_hash).unwrap();

        assert_eq!(hash1, hash2); // Same salt produces same hash
        assert_eq!(hash1, phc_hash); // Should match original hash
        assert!(hash1.starts_with("$argon2id$"));
    }
}
