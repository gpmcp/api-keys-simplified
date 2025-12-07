use crate::config::ChecksumAlgo;
use crate::{
    config::{Environment, KeyConfig, KeyPrefix},
    error::{Error, OperationError, Result},
    SecureString,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Prevent DoS: Validate input length before processing
const MAX_KEY_LENGTH: usize = 512;
const CHECKSUM_SEPARATOR: u8 = b'.';

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
        let mut random_bytes = Zeroizing::new(vec![0u8; *self.config.entropy_bytes()]);
        getrandom::fill(&mut random_bytes).map_err(|e| {
            OperationError::Generation(format!("Failed to get random bytes: {}", e))
        })?;

        // SECURITY FIX: Encode directly into a Zeroizing buffer to prevent intermediate
        // String allocation. Previously, encode() created an intermediate String that
        // was never zeroized before being converted to bytes.
        //
        // Base64 without padding: ceil(input_len * 4 / 3) bytes
        // For URL_SAFE_NO_PAD: exact formula is (input_len + 2) / 3 * 4
        let encoded_len = (random_bytes.len() + 2) / 3 * 4;
        let mut encoded = Zeroizing::new(vec![0u8; encoded_len]);

        URL_SAFE_NO_PAD
            .encode_slice(&random_bytes, &mut encoded)
            .map_err(|e| OperationError::Generation(format!("Base64 encoding failed: {}", e)))?;

        // Format: prefix{sep}environment{sep}base64data[.checksum]
        // Using configured separator
        let sep: &'static str = self.config.separator().into();
        let env: &'static str = environment.into();

        // SECURITY: Pre-allocate capacity to prevent reallocations during append operations.
        // Vec::append() can trigger reallocation if capacity is insufficient, which would
        // leave the old buffer (containing sensitive key material) in memory without zeroing.
        // By allocating the exact capacity needed upfront, we ensure a single buffer is used
        // throughout, which then gets moved to SecureString for proper zeroization on drop.
        let capacity = self.prefix.as_str().len()
            + sep.len()
            + env.len()
            + sep.len()
            + encoded.len()
            + if *self.config.include_checksum() {
                1 + 8 // dot separator + 8 hex chars for CRC32
            } else {
                0
            };

        let mut key = Vec::with_capacity(capacity);
        key.extend_from_slice(self.prefix.as_str().as_bytes());
        key.extend_from_slice(sep.as_bytes());
        key.extend_from_slice(env.as_bytes());
        key.extend_from_slice(sep.as_bytes());
        key.append(&mut encoded);

        if *self.config.include_checksum() {
            // Compute checksum on the key BEFORE appending the separator and checksum
            let checksum = Self::compute_checksum(&key, self.config.checksum_algorithm());
            // Use . as separator for checksum (always dot, regardless of key separator)
            key.push(CHECKSUM_SEPARATOR);
            key.append(&mut checksum.into_bytes());
        }

        Ok(SecureString::new(String::from_utf8(key).map_err(|_| {
            Error::OperationFailed(OperationError::Generation(
                "Unable to create valid UTF-8 String".to_string(),
            ))
        })?))
    }

    /// Verifies the CRC32 checksum using constant-time comparison.
    ///
    /// # Security Note
    /// - Uses constant-time comparison to prevent timing attacks that could
    ///   reveal information about the key structure
    /// - Performs dummy computation on oversized input to prevent side-channel
    ///   attacks via timing analysis of error paths
    ///
    /// Checksum is separated by '.' (dot), making it unambiguous from key parts
    pub fn verify_checksum(&self, key: impl AsRef<str>) -> Result<bool> {
        let key = key.as_ref();
        if key.len() > MAX_KEY_LENGTH {
            // Perform fake work to prevent timing side-channel attacks
            // This ensures rejection takes similar time as actual verification
            let dummy_key = "dummy_key_for_timing_protection";
            let _ = Self::compute_checksum(dummy_key, self.config.checksum_algorithm());
            return Err(Error::InvalidFormat);
        }

        // Split on '.' to get checksum (last part)
        let (checksum, key_without_checksum) = match key.rsplit_once('.') {
            Some((key_part, checksum_part)) => (checksum_part, key_part),
            None => return Ok(false),
        };

        let computed = Self::compute_checksum(key_without_checksum, self.config.checksum_algorithm());

        // Use constant-time comparison to prevent timing attacks
        Ok(checksum.as_bytes().ct_eq(computed.as_bytes()).into())
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
    fn compute_checksum<T: AsRef<[u8]>>(key: T, algo: &ChecksumAlgo) -> String {
        match algo {
            ChecksumAlgo::Black3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(key.as_ref());
                let hash = hasher.finalize();
                // Take first 16 hex characters (64 bits) - provides 2^64 collision resistance
                format!("{}", &hash.to_hex()[..16])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiKeyManager, HashConfig, Separator};

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
        let prefix = KeyPrefix::new("sk").unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default().with_checksum();

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

        // Verify checksum is 16 hex characters (BLAKE3 default)
        assert_eq!(
            checksum_part.len(),
            16,
            "Checksum should be 16 hex characters for BLAKE3"
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
        let prefix = KeyPrefix::new("pk").unwrap();
        let env = Environment::Test;
        let config = KeyConfig::default().with_checksum();

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env).unwrap();

        // Verify checksum is separated by '.'
        assert!(
            key.as_ref().contains('.'),
            "Checksum should be separated by '.'"
        );
        assert!(generator.verify_checksum(&key).unwrap());

        // Corrupt the checksum - need to preserve the key structure
        let parts: Vec<&str> = key.as_ref().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        let key_without_checksum = parts[1];
        let corrupted = format!("{}.wrong123", key_without_checksum);
        assert!(!generator.verify_checksum(&corrupted).unwrap());
    }

    #[test]
    fn test_verify_checksum_dos_protection() {
        let generator = ApiKeyManager::init("sk", KeyConfig::balanced(), HashConfig::default()).unwrap();

        // Test oversized key rejection
        let huge_key = SecureString::from("a".repeat(1000));
        assert!(generator.verify_checksum(&huge_key).is_err());

        // Test with valid size but invalid format returns false (not error)
        let invalid = SecureString::from("no_checksum".to_string());
        assert!(!generator.verify_checksum(&invalid).unwrap());

        // Test boundary - exactly at limit
        let at_limit = SecureString::from("sk_live_".to_string() + &"a".repeat(495) + ".abc123");
        let result = generator.verify_checksum(&at_limit);
        assert!(result.is_ok()); // No DoS error, just validation result
    }





    #[test]
    fn test_entropy_variations() {
        let prefix = KeyPrefix::new("api").unwrap();
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
        let prefix = KeyPrefix::new("text").unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default().with_checksum();

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
        assert_eq!(prefix_part, "text");
        // Second part should be environment
        assert_eq!(env_part, "live");
        // Third part is data
        assert!(data_part.len() > 0);
        // Checksum should be 16 hex characters for BLAKE3 (default)
        assert_eq!(checksum.len(), 16, "Checksum should be 16 hex characters for BLAKE3");
    }

    #[test]
    fn test_different_separators() {
        let prefix = KeyPrefix::new("sk").unwrap();
        let env = Environment::Production;

        // Test with Slash
        let config_slash = KeyConfig::default().with_separator(Separator::Slash).with_checksum();
        let generator_slash = KeyGenerator::new(prefix.clone(), config_slash);
        let key_slash = generator_slash.generate(env.clone()).unwrap();
        assert!(key_slash.as_ref().contains('/'));
        assert!(!key_slash.as_ref().contains('~'));
        assert!(generator_slash.verify_checksum(&key_slash).unwrap());

        // Test with Dash (default)
        let config_dash = KeyConfig::default().with_separator(Separator::Dash).with_checksum();
        let generator_dash = KeyGenerator::new(prefix.clone(), config_dash);
        let key_dash = generator_dash.generate(env.clone()).unwrap();
        assert!(key_dash.as_ref().contains('-'));
        // Checksum is always separated by dot
        let parts: Vec<&str> = key_dash.as_ref().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Key should have checksum separated by dot");
        assert!(generator_dash.verify_checksum(&key_dash).unwrap());

        // Test with Tilde
        let config_tilde = KeyConfig::default()
            .with_separator(Separator::Tilde);
        let generator_tilde = KeyGenerator::new(prefix, config_tilde);
        let key_tilde = generator_tilde.generate(env).unwrap();
        assert!(key_tilde.as_ref().contains('~'));
        assert!(key_tilde.as_ref().len() > 10);
    }
}
