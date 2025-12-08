use crate::error::{ConfigError, Error, Result};
use crate::token_parser::{parse_token, Parts};
use crate::HashConfig;
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
}

/// Represents the status of an API key after verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is valid
    Valid,
    /// Key is invalid (wrong key or hash mismatch)
    Invalid,
    /// Key has expired based on embedded expiration
    Expired,
}

impl KeyValidator {
    /// Maximum allowed length for API keys (prevents DoS via oversized inputs)
    const MAX_KEY_LENGTH: usize = 512;
    /// Maximum allowed length for password hashes (prevents DoS via malformed hashes)
    const MAX_HASH_LENGTH: usize = 512;

    pub fn new(
        hash_config: &HashConfig,
        has_checksum: bool,
    ) -> std::result::Result<KeyValidator, ConfigError> {
        let dummy_hash = format!("$argon2id$v=19$m={},t={},p={}$0bJKH8iokgID0PWXnrsXvw$oef42xfOKBQMkCpvoQTeVHLhsYf+EQWMc2u4Ebn1MUo", hash_config.memory_cost(), hash_config.time_cost(), hash_config.parallelism());
        let hash =
            PasswordHashString::new(&dummy_hash).map_err(|_| ConfigError::InvalidArgon2Hash)?;

        Ok(KeyValidator { hash, has_checksum })
    }

    fn verify_expiry(&self, parts: Parts) -> Result<KeyStatus> {
        if let Some(expiry) = parts.expiry_b64 {
            let decoded = URL_SAFE_NO_PAD
                .decode(expiry)
                .or(Err(Error::InvalidFormat))?;
            let expiry = i64::from_be_bytes(decoded.try_into().or(Err(Error::InvalidFormat))?);

            // TODO(ARCHITECTURE): time libs are platform dependent.
            // We should set an `infra` layer and abstract
            // out these libs.
            if chrono::Utc::now().timestamp() <= expiry {
                Ok(KeyStatus::Valid)
            } else {
                Ok(KeyStatus::Expired)
            }
        } else {
            Ok(KeyStatus::Valid)
        }
    }

    pub fn verify(&self, provided_key: &str, stored_hash: &str) -> Result<KeyStatus> {
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
            // Not sure if we should throw an error..
            // For now, we'll just check if verification succeeded.
            .is_ok();

        if !result {
            return Ok(KeyStatus::Invalid);
        }

        // We don't need to put dummy load beyond this point
        // since we have already processed the hash comparison.
        match self.verify_expiry(token_parts) {
            Ok(KeyStatus::Expired) => Ok(KeyStatus::Expired),
            _ => Ok(KeyStatus::Valid),
        }
    }
    fn dummy_load(&self) {
        // SECURITY: Perform dummy Argon2 verification to match timing of real verification
        // This prevents timing attacks that could distinguish between "invalid hash format"
        // and "valid hash but wrong password" errors
        let dummy_password =
            b"text-v1-test-okphUY-aqllb-qHoZDC9mVlm5sY9lvmm.AAAAAGk2Mvg.a54368d6331bf42dc18c";
        parse_token(dummy_password, self.has_checksum).ok();

        Argon2::default()
            .verify_password(dummy_password, &self.hash.password_hash())
            .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExposeSecret;
    use crate::{config::HashConfig, hasher::KeyHasher, SecureString};

    #[test]
    fn test_verification() {
        let key = SecureString::from("sk_live_testkey123".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&key).unwrap();

        let validator = KeyValidator::new(&HashConfig::default(), true).unwrap();
        assert_eq!(
            validator
                .verify(key.expose_secret(), hash.as_ref())
                .unwrap(),
            KeyStatus::Valid
        );
        assert_eq!(
            validator.verify("wrong_key", hash.as_ref()).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn test_invalid_hash_format() {
        let validator = KeyValidator::new(&HashConfig::default(), true).unwrap();
        let result = validator.verify("any_key", "invalid_hash");
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

        let validator = KeyValidator::new(&HashConfig::default(), true).unwrap();
        let result = validator.verify(&oversized_key, hash.as_ref());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_oversized_hash_rejection() {
        let oversized_hash = "a".repeat(513); // Exceeds MAX_HASH_LENGTH

        let validator = KeyValidator::new(&HashConfig::default(), true).unwrap();
        let result = validator.verify("valid_key", &oversized_hash);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_boundary_key_length() {
        let valid_key = SecureString::from("valid_key".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let hash = hasher.hash(&valid_key).unwrap();

        let validator = KeyValidator::new(&HashConfig::default(), true).unwrap();

        // Test at boundary (512 chars - should pass)
        let max_key = "a".repeat(512);
        let result = validator.verify(&max_key, hash.as_ref());
        assert!(result.is_ok()); // Should not error on length check

        // Test just over boundary (513 chars - should fail)
        let over_max_key = "a".repeat(513);
        let result = validator.verify(&over_max_key, hash.as_ref());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidFormat));
    }

    #[test]
    fn test_timing_oracle_protection() {
        let valid_key = SecureString::from("sk_live_testkey123".to_string());
        let hasher = KeyHasher::new(HashConfig::default());
        let valid_hash = hasher.hash(&valid_key).unwrap();

        let validator = KeyValidator::new(&HashConfig::default(), true).unwrap();

        let result1 = validator.verify("wrong_key", valid_hash.as_ref());
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), KeyStatus::Invalid);

        let result2 = validator.verify(valid_key.expose_secret(), "invalid_hash_format");
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), KeyStatus::Invalid);

        let result3 = validator.verify(valid_key.expose_secret(), "not even close to valid");
        assert!(result3.is_ok());
        assert_eq!(result3.unwrap(), KeyStatus::Invalid);
    }
}
