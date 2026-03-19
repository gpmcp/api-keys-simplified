//! BLAKE3 checksum computation and verification for DoS protection.
//!
//! This module provides fast integrity checking for API keys using BLAKE3.
//! Invalid keys are rejected in ~20us (checksum validation) instead of ~300ms
//! (Argon2 hashing), providing 2900x faster rejection and DoS protection.

use crate::config::{ChecksumAlgo, KeyConfig};
use crate::error::{Error, Result};
use crate::token_parser::parse_token;
use crate::{ExposeSecret, SecureString};
use subtle::ConstantTimeEq;

/// Maximum allowed API key length to prevent DoS via oversized inputs.
pub(crate) const MAX_KEY_LENGTH: usize = 512;

/// Separator between the key body and the checksum (always '.').
pub(crate) const CHECKSUM_SEPARATOR: u8 = b'.';

/// Handles checksum computation and verification for API keys.
///
/// Checksums provide a fast-path rejection of malformed keys before
/// the expensive Argon2 verification step.
#[derive(Clone)]
pub(crate) struct ChecksumVerifier {
    algorithm: ChecksumAlgo,
    length: usize,
    /// Dummy key for timing attack protection on error paths.
    dummy_key: SecureString,
}

impl ChecksumVerifier {
    /// Creates a new verifier from the key config and a pre-generated dummy key.
    pub(crate) fn new(config: &KeyConfig, dummy_key: SecureString) -> Self {
        Self {
            algorithm: config.checksum_algorithm().clone(),
            length: *config.checksum_length(),
            dummy_key,
        }
    }

    /// Returns whether checksums are enabled.
    pub(crate) fn is_enabled(&self) -> bool {
        self.length > 0
    }

    /// Verifies the BLAKE3 checksum using constant-time comparison.
    ///
    /// Uses `parse_token` to properly extract the checksum from keys
    /// with or without expiration timestamps.
    ///
    /// # Security Note
    /// - Uses constant-time comparison to prevent timing attacks that could
    ///   reveal information about the key structure.
    /// - Performs dummy computation on oversized input to prevent side-channel
    ///   attacks via timing analysis of error paths.
    ///
    /// # Key Format Support
    ///
    /// Handles all key formats correctly:
    /// - `key.checksum` - Key with checksum only
    /// - `key.expiry.checksum` - Key with expiry and checksum
    ///
    /// The checksum is computed over the key and expiry (if present), but NOT
    /// over the checksum itself.
    pub(crate) fn verify(&self, key: &SecureString) -> Result<bool> {
        let key_bytes = key.expose_secret();
        if key_bytes.len() > MAX_KEY_LENGTH {
            // Perform fake work to prevent timing side-channel attacks.
            // This ensures rejection takes similar time as actual verification.
            let _ = compute(self.dummy_key.expose_secret(), None, &self.algorithm, self.length);
            return Err(Error::InvalidFormat);
        }

        let has_checksum = self.length > 0;
        let parts = match parse_token(key_bytes, has_checksum) {
            Ok((_, parts)) => parts,
            Err(_) => {
                let _ = compute(self.dummy_key.expose_secret(), None, &self.algorithm, self.length);
                return Ok(false);
            }
        };

        // If no checksum present in the token, return false.
        let checksum_bytes = match parts.checksum {
            Some(c) => c,
            None => {
                let _ = compute(self.dummy_key.expose_secret(), None, &self.algorithm, self.length);
                return Ok(false);
            }
        };

        let computed = compute(parts.key, parts.expiry_b64, &self.algorithm, self.length);

        // Use constant-time comparison to prevent timing attacks.
        Ok(checksum_bytes.ct_eq(computed.as_bytes()).into())
    }
}

/// Computes a BLAKE3 integrity checksum over the given key material.
///
/// This is a pure function with no internal config checks.
/// The caller is responsible for only calling this when a checksum is needed.
///
/// # Panics
///
/// Panics if `length` is 0 — callers must check before calling.
pub(crate) fn compute<T: AsRef<[u8]>>(
    key: T,
    timestamp: Option<&[u8]>,
    algorithm: &ChecksumAlgo,
    length: usize,
) -> String {
    debug_assert!(length > 0, "compute() called with length 0; caller should guard");
    match algorithm {
        ChecksumAlgo::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(key.as_ref());
            if let Some(timestamp) = timestamp {
                hasher.update(timestamp);
            }
            let hash = hasher.finalize();
            hash.to_hex()[..length].to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiKeyManagerV0, HashConfig, KeyConfig, Separator};
    use crate::{config::KeyPrefix, generator::KeyGenerator, SecureStringExt};
    use crate::secure::new_secure_string;

    #[test]
    fn test_checksum_generation_with_dot_separator() {
        let prefix = KeyPrefix::new("pk").unwrap();
        let env = crate::config::Environment::Test;
        let config = KeyConfig::default();

        let generator = KeyGenerator::new(prefix, config.clone());
        let key = generator.generate(env, None).unwrap();

        let dummy = generator.generate(crate::config::Environment::Production, None).unwrap();
        let verifier = ChecksumVerifier::new(&config, dummy);

        // Verify checksum is separated by '.' (enabled by default)
        assert!(
            key.as_str().contains('.'),
            "Checksum should be separated by '.'"
        );
        assert!(verifier.verify(&key).unwrap());

        // Corrupt the checksum - need to preserve the key structure
        let parts: Vec<&str> = key.as_str().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        let key_without_checksum = parts[1];
        let corrupted = new_secure_string(format!("{}.wrong123", key_without_checksum));
        assert!(!verifier.verify(&corrupted).unwrap());
    }

    #[test]
    fn test_verify_checksum_dos_protection() {
        let generator = ApiKeyManagerV0::init(
            "sk",
            KeyConfig::balanced(),
            HashConfig::default(),
            std::time::Duration::ZERO,
        )
        .unwrap();

        // Test oversized key rejection
        let huge_key = new_secure_string("a".repeat(1000));
        assert!(generator.verify_checksum(&huge_key).is_err());

        // Test with valid size but invalid format returns false (not error)
        let invalid = new_secure_string("no_checksum".to_string());
        assert!(!generator.verify_checksum(&invalid).unwrap());

        // Test boundary - exactly at limit
        let at_limit = new_secure_string("sk_live_".to_string() + &"a".repeat(495) + ".abc123");
        let result = generator.verify_checksum(&at_limit);
        assert!(result.is_ok()); // No DoS error, just validation result
    }

    #[test]
    fn test_checksum_separator_is_dot() {
        let prefix = KeyPrefix::new("text").unwrap();
        let env = crate::config::Environment::Production;
        let config = KeyConfig::default();
        let checksum_len = *config.checksum_length();

        let generator = KeyGenerator::new(prefix, config.clone());
        let key = generator.generate(env, None).unwrap();

        // With dash separator and checksum (default): test-live-data.checksum
        // Should have exactly 1 dot (for checksum separator only)
        let dot_count = key.as_str().matches('.').count();
        assert_eq!(
            dot_count, 1,
            "Should have exactly one dot (for checksum separator)"
        );

        // Split on dot to separate checksum
        let parts: Vec<&str> = key.as_str().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Should split into key and checksum");

        let key_without_checksum = parts[1];
        let checksum = parts[0];

        // Split key on dash to verify structure (splitn to handle dashes in base64 data)
        let mut key_parts = key_without_checksum.splitn(3, '-');
        let prefix_part = key_parts.next().unwrap();
        let env_part = key_parts.next().unwrap();
        let data_part = key_parts.next().unwrap();

        // First part should be prefix
        assert_eq!(prefix_part, "text");
        // Second part should be environment
        assert_eq!(env_part, "live");
        // Third part is data
        assert!(!data_part.is_empty());
        assert_eq!(checksum.len(), checksum_len);
    }

    #[test]
    fn test_different_separators() {
        let prefix = KeyPrefix::new("sk").unwrap();
        let env = crate::config::Environment::Production;

        // Test with Slash
        let config_slash = KeyConfig::default().with_separator(Separator::Slash);
        let generator_slash = KeyGenerator::new(prefix.clone(), config_slash.clone());
        let key_slash = generator_slash.generate(env.clone(), None).unwrap();
        let dummy_slash = generator_slash.generate(crate::config::Environment::Production, None).unwrap();
        let verifier_slash = ChecksumVerifier::new(&config_slash, dummy_slash);
        assert!(key_slash.as_str().contains('/'));
        assert!(!key_slash.as_str().contains('~'));
        assert!(verifier_slash.verify(&key_slash).unwrap());

        // Test with Dash (default)
        let config_dash = KeyConfig::default().with_separator(Separator::Dash);
        let generator_dash = KeyGenerator::new(prefix.clone(), config_dash.clone());
        let key_dash = generator_dash.generate(env.clone(), None).unwrap();
        let dummy_dash = generator_dash.generate(crate::config::Environment::Production, None).unwrap();
        let verifier_dash = ChecksumVerifier::new(&config_dash, dummy_dash);
        assert!(key_dash.as_str().contains('-'));
        // Checksum is always separated by dot
        let parts: Vec<&str> = key_dash.as_str().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Key should have checksum separated by dot");
        assert!(verifier_dash.verify(&key_dash).unwrap());

        // Test with Tilde
        let config_tilde = KeyConfig::default().with_separator(Separator::Tilde);
        let generator_tilde = KeyGenerator::new(prefix, config_tilde);
        let key_tilde = generator_tilde.generate(env, None).unwrap();
        assert!(key_tilde.as_str().contains('~'));
        assert!(key_tilde.len() > 10);
    }

    #[test]
    fn test_compute_pure_function() {
        let algo = ChecksumAlgo::default();

        // Non-zero length returns a hex string
        let hex = compute(b"hello", None, &algo, 20);
        assert_eq!(hex.len(), 20);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        // Deterministic
        let hex2 = compute(b"hello", None, &algo, 20);
        assert_eq!(hex, hex2);

        // Different key => different checksum
        let hex3 = compute(b"world", None, &algo, 20);
        assert_ne!(hex, hex3);

        // With timestamp changes the result
        let hex4 = compute(b"hello", Some(b"timestamp"), &algo, 20);
        assert_ne!(hex, hex4);
    }
}
