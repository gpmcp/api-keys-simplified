use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use crate::error::{Error, OperationError, Result};

pub struct KeyValidator;

impl KeyValidator {
    /// Maximum allowed length for API keys (prevents DoS via oversized inputs)
    const MAX_KEY_LENGTH: usize = 512;
    /// Maximum allowed length for password hashes (prevents DoS via malformed hashes)
    const MAX_HASH_LENGTH: usize = 512;

    pub fn verify(provided_key: &str, stored_hash: &str) -> Result<bool> {
        // Input length validation to prevent DoS attacks
        if provided_key.len() > Self::MAX_KEY_LENGTH {
            return Err(Error::InvalidFormat);
        }
        if stored_hash.len() > Self::MAX_HASH_LENGTH {
            return Err(Error::InvalidFormat);
        }

        let parsed_hash = PasswordHash::new(stored_hash)
            .map_err(|e| OperationError::VerificationFailed(e.to_string()))?;

        let result = Argon2::default()
            .verify_password(provided_key.as_bytes(), &parsed_hash)
            .is_ok();

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::HashConfig, hasher::KeyHasher};

    #[test]
    fn test_verification() {
        let key = "sk_live_testkey123";
        let hash = KeyHasher::hash(key, &HashConfig::default()).unwrap();

        assert!(KeyValidator::verify(key, &hash).unwrap());
        assert!(!KeyValidator::verify("wrong_key", &hash).unwrap());
    }

    #[test]
    fn test_invalid_hash_format() {
        let result = KeyValidator::verify("any_key", "invalid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_key_rejection() {
        let oversized_key = "a".repeat(513); // Exceeds MAX_KEY_LENGTH
        let hash = KeyHasher::hash("valid_key", &HashConfig::default()).unwrap();
        
        let result = KeyValidator::verify(&oversized_key, &hash);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_oversized_hash_rejection() {
        let oversized_hash = "a".repeat(513); // Exceeds MAX_HASH_LENGTH
        
        let result = KeyValidator::verify("valid_key", &oversized_hash);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_boundary_key_length() {
        let hash = KeyHasher::hash("valid_key", &HashConfig::default()).unwrap();
        
        // Test at boundary (512 chars - should pass)
        let max_key = "a".repeat(512);
        let result = KeyValidator::verify(&max_key, &hash);
        assert!(result.is_ok()); // Should not error on length check
        
        // Test just over boundary (513 chars - should fail)
        let over_max_key = "a".repeat(513);
        let result = KeyValidator::verify(&over_max_key, &hash);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }
}
