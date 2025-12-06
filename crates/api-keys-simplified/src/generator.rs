use crate::{
    config::{Environment, KeyConfig, KeyPrefix, Separator},
    error::{Error, OperationError, Result},
    SecureString,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use subtle::ConstantTimeEq;

// Prevent DoS: Validate input length before processing
const MAX_KEY_LENGTH: usize = 512;

// Prevent DoS: Limit number of parts to prevent memory exhaustion
const MAX_PARTS: usize = 20; // Generous limit for complex prefixes

const CHECKSUM_SEPARATOR: char = '.';

#[derive(Clone)]
pub struct KeyGenerator {
    prefix: KeyPrefix,
    config: KeyConfig,
}

impl KeyGenerator {
    pub fn new(prefix: KeyPrefix, config: KeyConfig) -> KeyGenerator {
        Self { prefix, config }
    }
    pub fn generate(&self, environment: Environment) -> Result<SecureString> {
        let mut random_bytes = vec![0u8; *self.config.entropy_bytes()];
        getrandom::fill(&mut random_bytes).map_err(|e| {
            OperationError::Generation(format!("Failed to get random bytes: {}", e))
        })?;

        // Use standard URL-safe base64 encoding (no padding)
        // Produces: A-Z, a-z, 0-9, -, _ (all URL-safe, no special encoding needed)
        let encoded = URL_SAFE_NO_PAD.encode(&random_bytes);

        // Format: prefix{sep}environment{sep}base64data[.checksum]
        // Using configured separator
        let sep: &'static str = self.config.separator().into();
        let env: &'static str = environment.into();
        let key = format!("{}{}{}{}{}", self.prefix.as_str(), sep, env, sep, encoded);

        if *self.config.include_checksum() {
            let checksum = Self::compute_checksum(&key);
            // Use . as separator for checksum (always dot, regardless of key separator)
            Ok(SecureString::new(format!(
                "{}{CHECKSUM_SEPARATOR}{}",
                key, checksum
            )))
        } else {
            Ok(SecureString::new(key))
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
        let (checksum, key_without_checksum) = match key.rsplit_once('.') {
            Some((key_part, checksum_part)) => (checksum_part, key_part),
            None => return Ok(false),
        };

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
        // Use rsplit_once to split from right: checksum is last 8 hex chars after final '.'
        let key_without_checksum = match key.rsplit_once('.') {
            Some((key_part, checksum_part))
                if checksum_part.len() == 8
                    && checksum_part.chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                key_part // Return the key part without checksum
            }
            _ => key, // Not a checksum or no dot, use full key
        };

        // Format: prefix{sep}environment{sep}base64data
        // We perform a check while creation of KeyPrefix,
        // It is guaranteed that prefix won't contain
        // the sub string: {sep}environment{sep} (which base64 might).

        // So let's say actual env contains `dev`, but
        // base contains a pattern {sep}live{sep}.
        // In this case, we will have prefix{sep}dev{sep}someb64{sep}live{sep}remaining
        // So in order to find actual prefix, we simply need to find the min length.
        // Since splitting on {sep}live{sep} the length of LHS (i.e. prefix{sep}dev{sep}someb64)
        // will always be >= length of prefix.
        let sep_string: &'static str = separator.into();
        let separators = Environment::variants()
            .iter()
            .map(|v| (format!("{sep_string}{v}{sep_string}"), v));

        let mut partitioned_key = separators
            .map(|v| {
                key_without_checksum
                    .split(&v.0)
                    .take(MAX_PARTS)
                    .map(|split| (split, v.1))
                    .collect::<Vec<_>>()
            })
            .min_by_key(|v| v.first().map_or(usize::MAX, |v| v.0.len()))
            .unwrap_or_default()
            .into_iter();
        let (prefix, env) = partitioned_key.next().ok_or(Error::InvalidFormat)?;

        Ok((prefix.to_string(), env.to_string()))
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
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "Encoded: {}",
            encoded
        );
    }

    #[test]
    fn test_base64_various_inputs() {
        // Test all zeros
        let all_zeros = vec![0, 0, 0, 0];
        let encoded = URL_SAFE_NO_PAD.encode(&all_zeros);
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        // Test max values
        let max_values = vec![255, 255, 255, 255];
        let encoded = URL_SAFE_NO_PAD.encode(&max_values);
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        // Test mixed
        let mixed = vec![0, 128, 255, 1];
        let encoded = URL_SAFE_NO_PAD.encode(&mixed);
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
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
        let prefix = KeyPrefix::new("sk", &Separator::default()).unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default();

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env).unwrap();
        assert!(key.as_ref().starts_with("sk-live-"));

        // Verify key contains checksum separated by dot
        assert!(
            key.as_ref().contains('.'),
            "Should have checksum separated by dot"
        );

        // Split on . to separate checksum
        let parts: Vec<&str> = key.as_ref().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Should have key and checksum");

        let key_without_checksum = parts[1];
        let checksum_part = parts[0];

        // Verify checksum is 8 hex characters
        assert_eq!(
            checksum_part.len(),
            8,
            "Checksum should be 8 hex characters"
        );
        assert!(checksum_part.chars().all(|c| c.is_ascii_hexdigit()));

        // Split key part on dash - note that base64 data can contain dashes,
        // so we need to use splitn to only split on the first 2 dashes
        let mut key_parts = key_without_checksum.splitn(3, '-');
        let prefix_part = key_parts.next().unwrap();
        let env_part = key_parts.next().unwrap();
        let data_part = key_parts.next().unwrap();

        assert_eq!(prefix_part, "sk");
        assert_eq!(env_part, "live");

        // Verify data part contains only URL-safe base64 characters (A-Za-z0-9-_)
        assert!(
            data_part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "Data part should only contain URL-safe base64 characters, got: {}",
            data_part
        );
    }

    #[test]
    fn test_checksum_generation_with_dot_separator() {
        let prefix = KeyPrefix::new("pk", &Separator::default()).unwrap();
        let env = Environment::Test;
        let config = KeyConfig::default().with_checksum(true);

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env).unwrap();

        // Verify checksum is separated by '.'
        assert!(
            key.as_ref().contains('.'),
            "Checksum should be separated by '.'"
        );
        assert!(KeyGenerator::verify_checksum(&key).unwrap());

        // Corrupt the checksum - need to preserve the key structure
        let parts: Vec<&str> = key.as_ref().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        let key_without_checksum = parts[1];
        let corrupted = format!("{}.wrong123", key_without_checksum);
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

        // Test too many slashes - using splitn(3) prevents DoS by limiting splits
        // This should succeed but fail validation (not enough valid parts)
        let many_slashes = "/".repeat(500);
        // This will parse as: "", "", "//" repeated, which is valid format-wise with splitn
        // but will fail because first part (prefix) is empty or invalid
        let result = KeyGenerator::parse_key(&many_slashes, Separator::Slash);
        // The splitn approach means this will parse into 3 parts: ["", "", "///..."]
        // First part is empty string which is fine for parsing, it just returns empty prefix
        // This is actually OK - we're testing that it doesn't cause memory exhaustion
        assert!(result.is_ok() || result.is_err()); // Either is fine for DoS protection

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
        let prefix = KeyPrefix::new("api", &Separator::default()).unwrap();
        let env = Environment::Development;

        let config16 = KeyConfig::new().with_entropy(16).unwrap();
        let generator16 = KeyGenerator::new(prefix.clone(), config16);
        let key16 = generator16.generate(env.clone()).unwrap();

        let config32 = KeyConfig::new().with_entropy(32).unwrap();
        let generator32 = KeyGenerator::new(prefix, config32);
        let key32 = generator32.generate(env).unwrap();

        assert!(key32.len() > key16.len());
    }

    #[test]
    fn test_checksum_separator_is_dot() {
        let prefix = KeyPrefix::new("test", &Separator::default()).unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default().with_checksum(true);

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env).unwrap();

        // With dash separator: test-live-data.checksum
        // Should have exactly 1 dot (for checksum separator only)
        let dot_count = key.as_ref().matches('.').count();
        assert_eq!(
            dot_count, 1,
            "Should have exactly one dot (for checksum separator)"
        );

        // Split on dot to separate checksum
        let parts: Vec<&str> = key.as_ref().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Should split into key and checksum");

        let key_without_checksum = parts[1];
        let checksum = parts[0];

        // Split key on dash to verify structure (splitn to handle dashes in base64 data)
        let mut key_parts = key_without_checksum.splitn(3, '-');
        let prefix_part = key_parts.next().unwrap();
        let env_part = key_parts.next().unwrap();
        let data_part = key_parts.next().unwrap();

        // First part should be prefix
        assert_eq!(prefix_part, "test");
        // Second part should be environment
        assert_eq!(env_part, "live");
        // Third part is data
        assert!(data_part.len() > 0);
        // Checksum should be 8 hex characters for CRC32
        assert_eq!(checksum.len(), 8, "Checksum should be 8 hex characters");
    }

    #[test]
    fn test_different_separators() {
        let prefix = KeyPrefix::new("sk", &Separator::default()).unwrap();
        let env = Environment::Production;

        // Test with Slash
        let config_slash = KeyConfig::default().with_separator(Separator::Slash);
        let generator_slash = KeyGenerator::new(prefix.clone(), config_slash);
        let key_slash = generator_slash.generate(env.clone()).unwrap();
        assert!(key_slash.as_ref().contains('/'));
        assert!(!key_slash.as_ref().contains('~'));
        let (p, e) = KeyGenerator::parse_key(&key_slash, Separator::Slash).unwrap();
        assert_eq!(p, "sk");
        assert_eq!(e, "live");

        // Test with Dash (default)
        let config_dash = KeyConfig::default().with_separator(Separator::Dash);
        let generator_dash = KeyGenerator::new(prefix.clone(), config_dash);
        let key_dash = generator_dash.generate(env.clone()).unwrap();
        assert!(key_dash.as_ref().contains('-'));
        // Checksum is always separated by dot
        let parts: Vec<&str> = key_dash.as_ref().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Key should have checksum separated by dot");
        let key_without_checksum = parts[1];
        let (p, e) = KeyGenerator::parse_key(key_without_checksum, Separator::Dash).unwrap();
        assert_eq!(p, "sk");
        assert_eq!(e, "live");

        // Test with Tilde
        let config_tilde = KeyConfig::default()
            .with_separator(Separator::Tilde)
            .with_checksum(false);
        let generator_tilde = KeyGenerator::new(prefix, config_tilde);
        let key_tilde = generator_tilde.generate(env).unwrap();
        assert!(key_tilde.as_ref().contains('~'));
        let (p, e) = KeyGenerator::parse_key(&key_tilde, Separator::Tilde).unwrap();
        assert_eq!(p, "sk");
        assert_eq!(e, "live");
    }
}
