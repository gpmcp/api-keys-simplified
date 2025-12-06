use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};

use crate::{
    config::HashConfig,
    error::{OperationError, Result},
    SecureString,
};

pub struct KeyHasher;

impl KeyHasher {
    pub fn hash(key: &SecureString, config: &HashConfig) -> Result<String> {
        // Generate salt using OS cryptographic random source
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes)
            .map_err(|e| OperationError::Hashing(format!("Failed to generate salt: {}", e)))?;

        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        let params = Params::new(
            config.memory_cost(),
            config.time_cost(),
            config.parallelism(),
            None,
        )
        .map_err(|e| OperationError::Hashing(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let hash = argon2
            .hash_password(key.as_ref().as_bytes(), &salt)
            .map_err(|e| OperationError::Hashing(e.to_string()))?;

        Ok(hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashing() {
        let key = SecureString::new("sk_test_abc123xyz789".to_string());
        let config = HashConfig::default();

        let hash1 = KeyHasher::hash(&key, &config).unwrap();
        let hash2 = KeyHasher::hash(&key, &config).unwrap();

        assert_ne!(hash1, hash2); // Different salts
        assert!(hash1.starts_with("$argon2id$"));
    }

    #[test]
    fn test_different_configs() {
        let key = SecureString::new("test_key".to_string());

        let balanced_hash = KeyHasher::hash(&key, &HashConfig::balanced()).unwrap();
        let secure_hash = KeyHasher::hash(&key, &HashConfig::high_security()).unwrap();

        assert!(!balanced_hash.is_empty());
        assert!(!secure_hash.is_empty());
    }
}
