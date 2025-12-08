use crate::config::ChecksumAlgo;
use crate::token_parser::parse_token;
use crate::{
    config::{Environment, KeyConfig, KeyPrefix},
    error::{Error, OperationError, Result},
    ExposeSecret, SecureString,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// Prevent DoS: Validate input length before processing
const MAX_KEY_LENGTH: usize = 512;
const CHECKSUM_SEPARATOR: u8 = b'.';
static DUMMY_KEY: &str = "dummy_key_for_timing_protection";

#[derive(Clone)]
pub struct KeyGenerator {
    prefix: KeyPrefix,
    config: KeyConfig,
}

impl KeyGenerator {
    pub fn new(prefix: KeyPrefix, config: KeyConfig) -> KeyGenerator {
        Self { prefix, config }
    }

    fn generate_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut random_bytes = Zeroizing::new(vec![0u8; *self.config.entropy_bytes()]);
        getrandom::fill(&mut random_bytes).map_err(|e| {
            OperationError::Generation(format!("Failed to get random bytes: {}", e))
        })?;

        Ok(random_bytes)
    }

    pub fn generate(
        &self,
        environment: Environment,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<SecureString> {
        let bytes = self.generate_key()?;

        // SECURITY FIX: Encode directly into a Zeroizing buffer to prevent intermediate
        // String allocation. Previously, encode() created an intermediate String that
        // was never zeroized before being converted to bytes.
        //
        // Base64 without padding: ceil(input_len * 4 / 3) bytes
        // For URL_SAFE_NO_PAD: exact formula is (4 * input_len + 2) / 3
        let encoded_len = (4 * bytes.len()).div_ceil(3);
        let mut encoded = Zeroizing::new(vec![0u8; encoded_len]);

        URL_SAFE_NO_PAD
            .encode_slice(&bytes, &mut encoded)
            .map_err(|e| OperationError::Generation(format!("Base64 encoding failed: {}", e)))?;

        // Format depends on version:
        // Version 0: prefix{sep}env{sep}base64[.checksum]
        // Version N: prefix{sep}vN{sep}env{sep}base64[.checksum]
        let sep: &'static str = self.config.separator().into();
        let env: &'static str = environment.into();
        let version_component = self.config.version().component();

        // SECURITY: Pre-allocate capacity to prevent reallocations during append operations.
        // Vec::append() can trigger reallocation if capacity is insufficient, which would
        // leave the old buffer (containing sensitive key material) in memory without zeroing.
        // By allocating the exact capacity needed upfront, we ensure a single buffer is used
        // throughout, which then gets moved to SecureString for proper zeroization on drop.
        let checksum_length = match self.config.checksum_length() {
            0 => 0,
            n => n + 1, // Plus one for separator.
        };

        // Calculate capacity: prefix + [sep + version] + sep + env + sep + data + checksum
        let version_length = if version_component.is_empty() {
            0
        } else {
            sep.len() + version_component.len()
        };
        let exp_string = expiry.map(|e| URL_SAFE_NO_PAD.encode(e.timestamp().to_be_bytes()));
        let expiry_length = exp_string.as_ref().map(|b| b.len() + 1).unwrap_or(0);

        let capacity = self.prefix.as_str().len()
            + version_length
            + sep.len()
            + env.len()
            + sep.len()
            + encoded.len()
            + expiry_length
            + checksum_length;

        let mut key = Vec::with_capacity(capacity);
        key.extend_from_slice(self.prefix.as_str().as_bytes());

        // Add version component if present (between prefix and env)
        if !version_component.is_empty() {
            key.extend_from_slice(sep.as_bytes());
            key.extend_from_slice(version_component.as_bytes());
        }

        key.extend_from_slice(sep.as_bytes());
        key.extend_from_slice(env.as_bytes());
        key.extend_from_slice(sep.as_bytes());
        key.append(&mut encoded);

        let exp_bytes = exp_string.as_ref().map(|v| v.as_bytes());
        // Compute checksum on the key BEFORE appending the separator and checksum
        if let Some(checksum) = self.compute_checksum(&key, exp_bytes) {
            // Compute checksum on the key BEFORE appending the separator and checksum
            if let Some(b) = exp_bytes {
                key.push(CHECKSUM_SEPARATOR);
                key.extend_from_slice(b);
            }

            key.push(CHECKSUM_SEPARATOR);
            key.append(&mut checksum.into_bytes());
        }

        // SECURITY: It's SAFE to call from_utf8 here, since
        // that function will copy the vector.
        Ok(SecureString::from(String::from_utf8(key).map_err(
            |_| {
                Error::OperationFailed(OperationError::Generation(
                    "Unable to create valid UTF-8 String".to_string(),
                ))
            },
        )?))
    }

    /// Verifies the BLAKE3 checksum using constant-time comparison.
    ///
    /// Uses the `parse_token` function to properly extract checksum from keys
    /// with or without expiration timestamps.
    ///
    /// # Security Note
    /// - Uses constant-time comparison to prevent timing attacks that could
    ///   reveal information about the key structure
    /// - Performs dummy computation on oversized input to prevent side-channel
    ///   attacks via timing analysis of error paths
    ///
    /// # Key Format Support
    ///
    /// Handles all key formats correctly:
    /// - `key.checksum` - Key with checksum only
    /// - `key.expiry.checksum` - Key with expiry and checksum
    ///
    /// The checksum is computed over the key and expiry (if present), but NOT
    /// over the checksum itself.
    pub fn verify_checksum(&self, key: &SecureString) -> Result<bool> {
        let key_bytes = key.expose_secret().as_bytes();
        if key_bytes.len() > MAX_KEY_LENGTH {
            // Perform fake work to prevent timing side-channel attacks
            // This ensures rejection takes similar time as actual verification
            let _ = self.compute_checksum(DUMMY_KEY, None);
            return Err(Error::InvalidFormat);
        }

        // Use parse_token to extract checksum and key parts
        let has_checksum = *self.config.checksum_length() > 0;
        let parts = match parse_token(key_bytes, has_checksum) {
            Ok((_, parts)) => parts,
            Err(_) => {
                // If parsing fails, perform dummy work for timing consistency
                let _ = self.compute_checksum(DUMMY_KEY, None);
                return Ok(false);
            }
        };

        // If no checksum present, return false
        let checksum_bytes = match parts.checksum {
            Some(c) => c,
            None => {
                let _ = self.compute_checksum(DUMMY_KEY, None);
                return Ok(false);
            }
        };

        let computed = match self.compute_checksum(parts.key, parts.expiry_b64) {
            Some(computed) => computed,
            None => {
                let _ = self.compute_checksum(DUMMY_KEY, None);
                return Ok(false);
            }
        };

        // Use constant-time comparison to prevent timing attacks
        Ok(checksum_bytes.ct_eq(computed.as_bytes()).into())
    }

    /// Computes a integrity checksum.
    fn compute_checksum<T: AsRef<[u8]>>(&self, key: T, timestamp: Option<&[u8]>) -> Option<String> {
        // FIXME(ARCHITECTURE): We shouldn't perform this check here
        // This function should just take key and return hash.
        let checksum_len = *self.config.checksum_length();
        if checksum_len == usize::MIN {
            return None;
        }
        match self.config.checksum_algorithm() {
            ChecksumAlgo::Black3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(key.as_ref());
                if let Some(timestamp) = timestamp {
                    hasher.update(timestamp);
                }
                let hash = hasher.finalize();
                Some(hash.to_hex()[..checksum_len].to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiKeyManagerV0, HashConfig, Separator};
    use crate::{ExposeSecret, SecureStringExt};

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
        let config = KeyConfig::default();
        let checksum_len = *config.checksum_length();

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env, None).unwrap();
        assert!(key.expose_secret().starts_with("sk-live-"));

        // Verify key contains checksum separated by dot (enabled by default)
        assert!(
            key.expose_secret().contains('.'),
            "Should have checksum separated by dot"
        );

        // Split on . to separate checksum
        let parts: Vec<&str> = key.expose_secret().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Should have key and checksum");

        let key_without_checksum = parts[1];
        let checksum_part = parts[0];

        // Verify checksum is 16 hex characters (BLAKE3 default)
        assert_eq!(checksum_part.len(), checksum_len);
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
        let config = KeyConfig::default();

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env, None).unwrap();

        // Verify checksum is separated by '.' (enabled by default)
        assert!(
            key.expose_secret().contains('.'),
            "Checksum should be separated by '.'"
        );
        assert!(generator.verify_checksum(&key).unwrap());

        // Corrupt the checksum - need to preserve the key structure
        let parts: Vec<&str> = key.expose_secret().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        let key_without_checksum = parts[1];
        let corrupted = SecureString::from(format!("{}.wrong123", key_without_checksum));
        assert!(!generator.verify_checksum(&corrupted).unwrap());
    }

    #[test]
    fn test_verify_checksum_dos_protection() {
        let generator =
            ApiKeyManagerV0::init("sk", KeyConfig::balanced(), HashConfig::default()).unwrap();

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
        let key16 = generator16.generate(env.clone(), None).unwrap();

        let config32 = KeyConfig::new().with_entropy(32).unwrap();
        let generator32 = KeyGenerator::new(prefix, config32);
        let key32 = generator32.generate(env, None).unwrap();

        assert!(key32.len() > key16.len());
    }

    #[test]
    fn test_checksum_separator_is_dot() {
        let prefix = KeyPrefix::new("text").unwrap();
        let env = Environment::Production;
        let config = KeyConfig::default();
        let checksum_len = *config.checksum_length();

        let generator = KeyGenerator::new(prefix, config);
        let key = generator.generate(env, None).unwrap();

        // With dash separator and checksum (default): test-live-data.checksum
        // Should have exactly 1 dot (for checksum separator only)
        let dot_count = key.expose_secret().matches('.').count();
        assert_eq!(
            dot_count, 1,
            "Should have exactly one dot (for checksum separator)"
        );

        // Split on dot to separate checksum
        let parts: Vec<&str> = key.expose_secret().rsplitn(2, '.').collect();
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
        assert_eq!(checksum.len(), checksum_len);
    }

    #[test]
    fn test_different_separators() {
        let prefix = KeyPrefix::new("sk").unwrap();
        let env = Environment::Production;

        // Test with Slash
        let config_slash = KeyConfig::default().with_separator(Separator::Slash);
        let generator_slash = KeyGenerator::new(prefix.clone(), config_slash);
        let key_slash = generator_slash.generate(env.clone(), None).unwrap();
        assert!(key_slash.expose_secret().contains('/'));
        assert!(!key_slash.expose_secret().contains('~'));
        assert!(generator_slash.verify_checksum(&key_slash).unwrap());

        // Test with Dash (default)
        let config_dash = KeyConfig::default().with_separator(Separator::Dash);
        let generator_dash = KeyGenerator::new(prefix.clone(), config_dash);
        let key_dash = generator_dash.generate(env.clone(), None).unwrap();
        assert!(key_dash.expose_secret().contains('-'));
        // Checksum is always separated by dot
        let parts: Vec<&str> = key_dash.expose_secret().rsplitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "Key should have checksum separated by dot");
        assert!(generator_dash.verify_checksum(&key_dash).unwrap());

        // Test with Tilde
        let config_tilde = KeyConfig::default().with_separator(Separator::Tilde);
        let generator_tilde = KeyGenerator::new(prefix, config_tilde);
        let key_tilde = generator_tilde.generate(env, None).unwrap();
        assert!(key_tilde.expose_secret().contains('~'));
        assert!(key_tilde.len() > 10);
    }
}
