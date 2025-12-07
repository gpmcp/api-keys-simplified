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
    pub fn hash(&self, key: &SecureString) -> Result<String> {
        // Generate salt using OS cryptographic random source
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes)
            .map_err(|e| OperationError::Hashing(format!("Failed to generate salt: {}", e)))?;

        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        let params = Params::new(
            *self.config.memory_cost(),
            *self.config.time_cost(),
            *self.config.parallelism(),
            None,
        )
        .map_err(|e| OperationError::Hashing(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let hash = argon2
            .hash_password(key.expose_secret().as_bytes(), &salt)
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

        assert_ne!(hash1, hash2); // Different salts
        assert!(hash1.starts_with("$argon2id$"));
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
}
