use crate::error::{ConfigError, Error, Result};
use crate::token_parser::{parse_token, Parts};
use crate::SecureString;
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use password_hash::PasswordHashString;

#[derive(Clone)]
pub struct KeyValidator {
    hash: PasswordHashString,
    has_checksum: bool,
    /// Dummy password for timing attack protection (should be a generated API key)
    dummy_password: SecureString,
}

/// Represents the status of an API key after verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is valid
    Valid,
    /// Key is invalid (wrong key or hash mismatch)
    Invalid,
}

impl KeyValidator {
    /// Maximum allowed length for API keys (prevents DoS via oversized inputs)
    const MAX_KEY_LENGTH: usize = 512;
    /// Maximum allowed length for password hashes (prevents DoS via malformed hashes)
    const MAX_HASH_LENGTH: usize = 512;

    pub fn new(
        has_checksum: bool,
        dummy_key: SecureString,
        dummy_hash: String,
    ) -> std::result::Result<KeyValidator, ConfigError> {
        let hash =
            PasswordHashString::new(&dummy_hash).map_err(|_| ConfigError::InvalidArgon2Hash)?;

        Ok(KeyValidator {
            hash,
            has_checksum,
            dummy_password: dummy_key,
        })
    }

    fn verify_expiry(&self, parts: Parts, expiry_grace_period: std::time::Duration) -> Result<KeyStatus> {
        if let Some(expiry) = parts.expiry_b64 {
            let decoded = URL_SAFE_NO_PAD
                .decode(expiry)
                .or(Err(Error::InvalidFormat))?;
            let expiry_timestamp = i64::from_be_bytes(decoded.try_into().or(Err(Error::InvalidFormat))?);

            let current_time = chrono::Utc::now().timestamp();
            let grace_seconds = expiry_grace_period.as_secs() as i64;
            
            // Key is invalid if it expired more than grace_period ago
            // This ensures once a key expires beyond the grace period, it stays expired
            // even if the clock goes backwards
            if expiry_timestamp + grace_seconds < current_time {
                return Ok(KeyStatus::Invalid);
            }
            Ok(KeyStatus::Valid)
        } else {
            Ok(KeyStatus::Valid)
        }
    }

    pub fn verify(
        &self,
        provided_key: &str,
        stored_hash: &str,
        expiry_grace_period: std::time::Duration,
    ) -> Result<KeyStatus> {
        // Input length validation to prevent DoS attacks
        if provided_key.len() > Self::MAX_KEY_LENGTH {
            self.dummy_load();
            return Err(Error::InvalidFormat);
        }
        if stored_hash.len() > Self::MAX_HASH_LENGTH {
            self.dummy_load();
            return Err(Error::InvalidFormat);
        }

        let token_parts = match parse_token(provided_key.as_bytes(), self.has_checksum) {
            Ok(token_parts) => token_parts.1,
            Err(_) => {
                self.dummy_load();
                return Ok(KeyStatus::Invalid);
            }
        };

        // Parse the stored hash - if parsing fails, perform dummy verification
        // to ensure constant timing and prevent user enumeration attacks
        let parsed_hash = match PasswordHash::new(stored_hash) {
            Ok(h) => h,
            Err(_) => {
                self.dummy_load();
                return Ok(KeyStatus::Invalid);
            }
        };
        let result = Argon2::default()
            .verify_password(provided_key.as_bytes(), &parsed_hash)
            .is_ok();

        let argon_result = if result {
            KeyStatus::Valid
        } else {
            KeyStatus::Invalid
        };

        // SECURITY: Force evaluation of expiry check BEFORE the match to ensure
        // constant-time execution. This prevents the compiler from short-circuiting
        // the expiry check when argon_result is Invalid, which would create a timing oracle.
        let expiry_result = self.verify_expiry(token_parts, expiry_grace_period)?;

        match (argon_result, expiry_result) {
            (KeyStatus::Invalid, _) | (_, KeyStatus::Invalid) => Ok(KeyStatus::Invalid),
            _ => Ok(KeyStatus::Valid),
        }
    }
    fn dummy_load(&self) {
        // SECURITY: Perform dummy Argon2 verification to match timing of real verification
        // This prevents timing attacks that could distinguish between "invalid hash format"
        // and "valid hash but wrong password" errors
        use crate::ExposeSecret;
        let dummy_bytes = self.dummy_password.expose_secret().as_bytes();
        parse_token(dummy_bytes, self.has_checksum).ok();

        Argon2::default()
            .verify_password(dummy_bytes, &self.hash.password_hash())
            .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;
    use crate::{config::HashConfig, hasher::KeyHasher, SecureString};

    fn dummy_key_and_hash() -> (SecureString, String) {
        let key = SecureString::from("sk-live-dummy123test".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&key).unwrap();
        (key, hash)
    }

    #[test]
    fn test_verification() {
        let key = SecureString::from("sk_live_testkey123".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&key).unwrap();

        let (dummy_key, dummy_hash) = dummy_key_and_hash();
        let validator =
            KeyValidator::new(true, dummy_key, dummy_hash).unwrap();
        assert_eq!(
            validator
                .verify(key.expose_secret(), hash.as_ref(), std::time::Duration::ZERO)
                .unwrap(),
            KeyStatus::Valid
        );
        assert_eq!(
            validator.verify("wrong_key", hash.as_ref(), std::time::Duration::ZERO).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn test_invalid_hash_format() {
        let (dummy_key, dummy_hash) = dummy_key_and_hash();
        let validator =
            KeyValidator::new(true, dummy_key, dummy_hash).unwrap();
        let result = validator.verify("any_key", "invalid_hash", std::time::Duration::ZERO);
        // After timing oracle fix: invalid hash format returns Ok(Invalid) instead of Err
        // to prevent timing-based user enumeration attacks
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), KeyStatus::Invalid);
    }

    #[test]
    fn test_oversized_key_rejection() {
        let oversized_key = "a".repeat(513); // Exceeds MAX_KEY_LENGTH
        let valid_key = SecureString::from("valid_key".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&valid_key).unwrap();

        let (dummy_key, dummy_hash) = dummy_key_and_hash();
        let validator =
            KeyValidator::new(true, dummy_key, dummy_hash).unwrap();
        let result = validator.verify(&oversized_key, hash.as_ref(), std::time::Duration::ZERO);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_oversized_hash_rejection() {
        let oversized_hash = "a".repeat(513); // Exceeds MAX_HASH_LENGTH

        let (dummy_key, dummy_hash) = dummy_key_and_hash();
        let validator =
            KeyValidator::new(true, dummy_key, dummy_hash).unwrap();
        let result = validator.verify("valid_key", &oversized_hash, std::time::Duration::ZERO);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_boundary_key_length() {
        let valid_key = SecureString::from("valid_key".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&valid_key).unwrap();

        let (dummy_key, dummy_hash) = dummy_key_and_hash();
        let validator =
            KeyValidator::new(true, dummy_key, dummy_hash).unwrap();

        // Test at boundary (512 chars - should pass)
        let max_key = "a".repeat(512);
        let result = validator.verify(&max_key, hash.as_ref(), std::time::Duration::ZERO);
        assert!(result.is_ok()); // Should not error on length check

        // Test just over boundary (513 chars - should fail)
        let over_max_key = "a".repeat(513);
        let result = validator.verify(&over_max_key, hash.as_ref(), std::time::Duration::ZERO);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_timing_oracle_protection() {
        let valid_key = SecureString::from("sk_live_testkey123".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let valid_hash = hasher.hash(&valid_key).unwrap();

        let (dummy_key, dummy_hash) = dummy_key_and_hash();
        let validator =
            KeyValidator::new(true, dummy_key, dummy_hash).unwrap();

        let result1 = validator.verify("wrong_key", valid_hash.as_ref(), std::time::Duration::ZERO);
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), KeyStatus::Invalid);

        let result2 = validator.verify(valid_key.expose_secret(), "invalid_hash_format", std::time::Duration::ZERO);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), KeyStatus::Invalid);

        let result3 = validator.verify(valid_key.expose_secret(), "not even close to valid", std::time::Duration::ZERO);
        assert!(result3.is_ok());
        assert_eq!(result3.unwrap(), KeyStatus::Invalid);
    }
}
