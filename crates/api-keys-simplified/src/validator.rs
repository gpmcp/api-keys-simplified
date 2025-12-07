use crate::error::{Error, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};

pub struct KeyValidator;

impl KeyValidator {
    /// Maximum allowed length for API keys (prevents DoS via oversized inputs)
    const MAX_KEY_LENGTH: usize = 512;
    /// Maximum allowed length for password hashes (prevents DoS via malformed hashes)
    const MAX_HASH_LENGTH: usize = 512;

    pub fn verify(provided_key: &str, stored_hash: &str) -> Result<bool> {
        // Input length validation to prevent DoS attacks
        if provided_key.len() > Self::MAX_KEY_LENGTH {
            dummy_load();
            return Err(Error::InvalidFormat);
        }
        if stored_hash.len() > Self::MAX_HASH_LENGTH {
            dummy_load();
            return Err(Error::InvalidFormat);
        }

        // Parse the stored hash - if parsing fails, perform dummy verification
        // to ensure constant timing and prevent user enumeration attacks
        let parsed_hash = match PasswordHash::new(stored_hash) {
            Ok(h) => h,
            Err(_) => {
                dummy_load();
                return Ok(false);
            }
        };
        let result = Argon2::default()
            .verify_password(provided_key.as_bytes(), &parsed_hash)
            // Not sure if we should throw an error..
            // For now, we'll just check if verification succeeded.
            .is_ok();

        Ok(result)
    }
}

fn dummy_load() {
    // SECURITY: Perform dummy Argon2 verification to match timing of real verification
    // This prevents timing attacks that could distinguish between "invalid hash format"
    // and "valid hash but wrong password" errors
    static DUMMY_HASH: &str = "$argon2id$v=19$m=47104,t=1,p=1$0bJKH8iokgID0PWXnrsXvw$oef42xfOKBQMkCpvoQTeVHLhsYf+EQWMc2u4Ebn1MUo";
    let dummy_password = b"dummy_password_for_timing";

    if let Ok(dummy_parsed) = PasswordHash::new(DUMMY_HASH) {
        let _ = Argon2::default().verify_password(dummy_password, &dummy_parsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::HashConfig, hasher::KeyHasher, SecureString};

    #[test]
    fn test_verification() {
        let key = SecureString::new("sk_live_testkey123".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&key).unwrap();

        assert!(KeyValidator::verify(key.as_ref(), hash.as_ref()).unwrap());
        assert!(!KeyValidator::verify("wrong_key", hash.as_ref()).unwrap());
    }

    #[test]
    fn test_invalid_hash_format() {
        let result = KeyValidator::verify("any_key", "invalid_hash");
        // After timing oracle fix: invalid hash format returns Ok(false) instead of Err
        // to prevent timing-based user enumeration attacks
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_oversized_key_rejection() {
        let oversized_key = "a".repeat(513); // Exceeds MAX_KEY_LENGTH
        let valid_key = SecureString::new("valid_key".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&valid_key).unwrap();

        let result = KeyValidator::verify(&oversized_key, hash.as_ref());
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
        let valid_key = SecureString::new("valid_key".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&valid_key).unwrap();

        // Test at boundary (512 chars - should pass)
        let max_key = "a".repeat(512);
        let result = KeyValidator::verify(&max_key, hash.as_ref());
        assert!(result.is_ok()); // Should not error on length check

        // Test just over boundary (513 chars - should fail)
        let over_max_key = "a".repeat(513);
        let result = KeyValidator::verify(&over_max_key, hash.as_ref());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_timing_oracle_protection() {
        let valid_key = SecureString::new("sk_live_testkey123".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let valid_hash = hasher.hash(&valid_key).unwrap();

        let result1 = KeyValidator::verify("wrong_key", valid_hash.as_ref());
        assert!(result1.is_ok());
        assert!(!result1.unwrap());

        let result2 = KeyValidator::verify(valid_key.as_ref(), "invalid_hash_format");
        assert!(result2.is_ok());
        assert!(!result2.unwrap());

        let result3 = KeyValidator::verify(valid_key.as_ref(), "not even close to valid");
        assert!(result3.is_ok());
        assert!(!result3.unwrap());
    }
}
