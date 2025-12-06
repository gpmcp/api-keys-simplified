use crate::{
    config::{Environment, KeyConfig, KeyPrefix, Separator},
    error::{Error, OperationError, Result},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use subtle::ConstantTimeEq;

// Prevent DoS: Validate input length before processing
const MAX_KEY_LENGTH: usize = 512;

// Prevent DoS: Limit number of parts to prevent memory exhaustion
const MAX_PARTS: usize = 100; // Generous limit for complex prefixes

pub struct KeyGenerator;

impl KeyGenerator {
    pub fn generate(
        prefix: KeyPrefix,
        environment: Environment,
        config: &KeyConfig,
    ) -> Result<String> {
        let mut random_bytes = vec![0u8; config.entropy_bytes];
        getrandom::fill(&mut random_bytes).map_err(|e| {
            OperationError::GenerationFailed(format!("Failed to get random bytes: {}", e))
        })?;

        // Use standard URL-safe base64 encoding (no padding)
        // Produces: A-Z, a-z, 0-9, -, _ (all URL-safe, no special encoding needed)
        let encoded = URL_SAFE_NO_PAD.encode(&random_bytes);

        // Format: prefix{sep}environment{sep}base64data[.checksum]
        // Using configured separator
        let sep = config.separator.to_string();
        let key = format!("{}{}{}{}{}", prefix.as_str(), sep, environment.as_str(), sep, encoded);

        if config.include_checksum {
            let checksum = Self::compute_checksum(&key);
            // Use . as separator for checksum (always dot, regardless of key separator)
            // FIXME: We can use key separator here too.
            Ok(format!("{}.{}", key, checksum))
        } else {
            Ok(key)
        }
    }

    /// Computes a **non-cryptographic** integrity checksum using CRC32.
    ///
    /// # Security Note
    ///
    /// CRC32 is NOT collision-resistant and should NOT be relied upon for security.
    /// This checksum serves only to:
    /// - Detect accidental corruption (typos, truncation)
    /// - Enable fast rejection of malformed keys before expensive Argon2 verification
    ///
    /// The Argon2 hash provides actual cryptographic authentication.
    /// An attacker can find CRC32 collisions with ~65,536 attempts (birthday attack).
    fn compute_checksum(key: &str) -> String {
        let crc = crc32fast::hash(key.as_bytes());
        format!("{:08x}", crc) // 8 hex characters for full 32-bit CRC
    }

    /// Verifies the CRC32 checksum using constant-time comparison.
    ///
    /// # Security Note
    /// Uses constant-time comparison to prevent timing attacks that could
    /// reveal information about the key structure.
    /// 
    /// Checksum is separated by '.' (dot), making it unambiguous from key parts
    pub fn verify_checksum(key: impl AsRef<str>) -> Result<bool> {
        let key = key.as_ref();
        if key.len() > MAX_KEY_LENGTH {
            return Err(Error::InvalidFormat);
        }

        // Split on '.' to get checksum (last part)
        let parts: Vec<&str> = key.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Ok(false);
        }

        let (checksum, key_without_checksum) = (parts[0], parts[1]);
        let computed = Self::compute_checksum(key_without_checksum);

        // Use constant-time comparison to prevent timing attacks
        if checksum.len() != computed.len() {
            return Ok(false);
        }
        Ok(checksum.as_bytes().ct_eq(computed.as_bytes()).into())
    }

    pub fn parse_key(key: impl AsRef<str>, separator: Separator) -> Result<(String, String)> {
        let key = key.as_ref();
        
        // Prevent DoS: Validate input length before processing
        if key.len() > MAX_KEY_LENGTH {
            return Err(Error::InvalidFormat);
        }

        // Remove checksum if present (always the last part after final '.')
        // Checksum is always separated by '.' regardless of key separator
        // Use rsplitn to split from right: checksum is last 8 hex chars after final '.'
        let key_without_checksum = if key.contains('.') {
            let parts: Vec<&str> = key.rsplitn(2, '.').collect();
            if parts.len() == 2 {
                // Check if the last part looks like a checksum (8 hex characters)
                if parts[0].len() == 8 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
                    parts[1] // Return the key part without checksum
                } else {
                    key // Not a checksum, use full key
                }
            } else {
                key
            }
        } else {
            key
        };

        // Format: prefix{sep}environment{sep}base64data
        // Split on configured separator
        let sep_str = separator.to_string();
        let parts: Vec<&str> = key_without_checksum.split(sep_str.as_str()).take(MAX_PARTS + 1).collect();

        if parts.len() > MAX_PARTS {
            return Err(Error::InvalidFormat);
        }

        if parts.len() != 3 {
            return Err(Error::InvalidFormat);
        }

        // Format is exactly: prefix{sep}environment{sep}data
        let prefix = parts[0].to_string();
        let env = parts[1].to_string();

        Ok((prefix, env))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_url_safe_encoding() {
        // Test that URL_SAFE_NO_PAD works correctly
        let bytes = vec![0, 1, 2, 255];
        let encoded = URL_SAFE_NO_PAD.encode(&bytes);
        
        // URL-safe base64 uses: A-Z, a-z, 0-9, -, _
        assert!(!encoded.contains('+'), "Should not contain plus");
        assert!(!encoded.contains('/'), "Should not contain slash");
        assert!(!encoded.contains('='), "Should not contain padding");
        
        // Verify all characters are URL-safe
        assert!(encoded.chars().all(|c| 
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        ), "Encoded: {}", encoded);
    }

    #[test]
    fn test_base64_various_inputs() {
        // Test all zeros
        let all_zeros = vec![0, 0, 0, 0];
        let encoded = URL_SAFE_NO_PAD.encode(&all_zeros);
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        
        // Test max values
        let max_values = vec![255, 255, 255, 255];
        let encoded = URL_SAFE_NO_PAD.encode(&max_values);
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        
        // Test mixed
        let mixed = vec![0, 128, 255, 1];
        let encoded = URL_SAFE_NO_PAD.encode(&mixed);
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_base64_empty() {
        let empty: Vec<u8> = vec![];
        let encoded = URL_SAFE_NO_PAD.encode(&empty);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_base64_deterministic() {
        // Same input should always produce same output
        let bytes = vec![1, 2, 3, 4, 5];
        let encoded1 = URL_SAFE_NO_PAD.encode(&bytes);
        let encoded2 = URL_SAFE_NO_PAD.encode(&bytes);
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_key_generation() {
        let prefix = KeyPrefix::new("sk").unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default();

        let key = KeyGenerator::generate(prefix, env, &config).unwrap();
        assert!(key.starts_with("sk.live."));
        
        // Verify key contains only valid characters
        // Format: prefix.env.base64data[.checksum] (with dot separator by default)
        // Split on . to get parts
        let dot_parts: Vec<&str> = key.split('.').collect();
        // With checksum enabled by default, we'll have: prefix, env, data, checksum (4 parts)
        // Without checksum: prefix, env, data (3 parts)
        assert!(dot_parts.len() >= 3, "Should have at least prefix, env, and data");
        
        // Get the data part (third element)
        // If there are 4 parts, last one is checksum
        let data_part = if dot_parts.len() == 4 {
            dot_parts[2]
        } else {
            dot_parts[2]
        };
        
        // Verify data part contains only URL-safe base64 characters (A-Za-z0-9-_)
        assert!(data_part.chars().all(|c| 
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        ), "Data part should only contain URL-safe base64 characters, got: {}", data_part);
    }

    #[test]
    fn test_checksum_generation_with_dot_separator() {
        let prefix = KeyPrefix::new("pk").unwrap();
        let env = Environment::Test;
        let config = KeyConfig::default().with_checksum(true);

        let key = KeyGenerator::generate(prefix, env, &config).unwrap();
        
        // Verify checksum is separated by '.'
        assert!(key.contains('.'), "Checksum should be separated by '.'");
        assert!(KeyGenerator::verify_checksum(&key).unwrap());

        // Corrupt the checksum
        let parts: Vec<&str> = key.split('.').collect();
        let corrupted = format!("{}.wrong", parts[0]);
        assert!(!KeyGenerator::verify_checksum(&corrupted).unwrap());
    }

    #[test]
    fn test_verify_checksum_dos_protection() {
        // Test oversized key rejection
        let huge_key = "a".repeat(1000);
        assert!(KeyGenerator::verify_checksum(&huge_key).is_err());

        // Test with valid size but invalid format returns false (not error)
        let invalid = "no_checksum";
        assert!(!KeyGenerator::verify_checksum(invalid).unwrap());

        // Test boundary - exactly at limit
        let at_limit = "sk_live_".to_string() + &"a".repeat(495) + ".abc123";
        let result = KeyGenerator::verify_checksum(&at_limit);
        assert!(result.is_ok()); // No DoS error, just validation result
    }

    #[test]
    fn test_parse_key_dos_protection() {
        // Test oversized key rejection
        let huge_key = "a".repeat(1000);
        assert!(KeyGenerator::parse_key(&huge_key, Separator::Slash).is_err());

        // Test too many slashes (memory exhaustion attempt)
        let many_slashes = "/".repeat(500);
        assert!(KeyGenerator::parse_key(&many_slashes, Separator::Slash).is_err());

        // Test valid key still works
        let valid = "sk/live/abc123";
        assert!(KeyGenerator::parse_key(valid, Separator::Slash).is_ok());
        
        // Test valid key with checksum
        let with_checksum = "sk/live/abc123.abc123";
        assert!(KeyGenerator::parse_key(with_checksum, Separator::Slash).is_ok());
    }

    #[test]
    fn test_key_parsing() {
        let key = "sk/live/abc123xyz789";
        let (prefix, env) = KeyGenerator::parse_key(key, Separator::Slash).unwrap();
        assert_eq!(prefix, "sk");
        assert_eq!(env, "live");
        
        // Test parsing with checksum (should ignore checksum)
        let key_with_checksum = "sk/live/abc123xyz789.checksm";
        let (prefix, env) = KeyGenerator::parse_key(key_with_checksum, Separator::Slash).unwrap();
        assert_eq!(prefix, "sk");
        assert_eq!(env, "live");
    }

    #[test]
    fn test_entropy_variations() {
        let prefix = KeyPrefix::new("api").unwrap();
        let env = Environment::Development;

        let config16 = KeyConfig::new().with_entropy(16).unwrap();
        let key16 = KeyGenerator::generate(prefix.clone(), env.clone(), &config16).unwrap();

        let config32 = KeyConfig::new().with_entropy(32).unwrap();
        let key32 = KeyGenerator::generate(prefix, env, &config32).unwrap();

        assert!(key32.len() > key16.len());
    }
    
    #[test]
    fn test_checksum_separator_is_dot() {
        let prefix = KeyPrefix::new("test").unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default().with_checksum(true);

        let key = KeyGenerator::generate(prefix, env, &config).unwrap();
        
        // With dot separator: test.live.data.checksum (4 parts, 3 dots)
        // Count separators
        let dot_count = key.matches('.').count();
        
        // Should have 3 dots total (2 for key structure + 1 for checksum separator)
        assert_eq!(dot_count, 3, "Should have exactly three dots (2 for structure, 1 for checksum)");
        
        // Verify format: should be able to split on . and get 4 parts
        let parts: Vec<&str> = key.split('.').collect();
        assert_eq!(parts.len(), 4, "Should split into prefix, env, data, and checksum");
        
        // First part should be prefix
        assert_eq!(parts[0], "test");
        // Second part should be environment
        assert_eq!(parts[1], "live");
        // Third part is data
        assert!(parts[2].len() > 0);
        // Fourth part should be the checksum (8 hex characters for CRC32)
        assert_eq!(parts[3].len(), 8, "Checksum should be 8 hex characters");
    }

    #[test]
    fn test_different_separators() {
        let prefix = KeyPrefix::new("sk").unwrap();
        let env = Environment::Production;
        
        // Test with Slash (default)
        let config_slash = KeyConfig::default().with_separator(Separator::Slash);
        let key_slash = KeyGenerator::generate(prefix.clone(), env.clone(), &config_slash).unwrap();
        assert!(key_slash.contains('/'));
        assert!(!key_slash.contains('~'));
        let (p, e) = KeyGenerator::parse_key(&key_slash, Separator::Slash).unwrap();
        assert_eq!(p, "sk");
        assert_eq!(e, "live");

        // Test with Dot (must disable checksum since dot is used for checksum separator)
        let config_dot = KeyConfig::default()
            .with_separator(Separator::Dot)
            .with_checksum(false);
        let key_dot = KeyGenerator::generate(prefix.clone(), env.clone(), &config_dot).unwrap();
        assert!(key_dot.contains('.'));
        assert!(!key_dot.ends_with('.'));  // No trailing dot (no checksum)
        let (p, e) = KeyGenerator::parse_key(&key_dot, Separator::Dot).unwrap();
        assert_eq!(p, "sk");
        assert_eq!(e, "live");

        // Test with Tilde
        let config_tilde = KeyConfig::default().with_separator(Separator::Tilde).with_checksum(false);
        let key_tilde = KeyGenerator::generate(prefix, env, &config_tilde).unwrap();
        assert!(key_tilde.contains('~'));
        let (p, e) = KeyGenerator::parse_key(&key_tilde, Separator::Tilde).unwrap();
        assert_eq!(p, "sk");
        assert_eq!(e, "live");
    }
}
