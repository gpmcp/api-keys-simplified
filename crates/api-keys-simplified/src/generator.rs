//! Cryptographically secure API key generation.
//!
//! This module is responsible solely for generating API key strings with
//! the correct format: `prefix[{sep}version]{sep}env{sep}base64[.expiry][.checksum]`.
//! Checksum computation is delegated to the `checksum` module.

use crate::checksum::{self, CHECKSUM_SEPARATOR};
use crate::{
    config::{Environment, KeyConfig, KeyPrefix},
    error::{OperationError, Result},
    SecureString,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct KeyGenerator {
    prefix: KeyPrefix,
    config: KeyConfig,
}

impl KeyGenerator {
    /// Creates a new key generator. This is infallible since it only stores config.
    pub fn new(prefix: KeyPrefix, config: KeyConfig) -> KeyGenerator {
        Self { prefix, config }
    }

    fn generate_random_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
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
        let bytes = self.generate_random_bytes()?;

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

        self.assemble_key(encoded, environment, expiry)
    }

    /// Assembles the final key string from its components.
    ///
    /// # Key Format
    ///
    /// - Version 0: `prefix{sep}env{sep}base64[.expiry][.checksum]`
    /// - Version N: `prefix{sep}vN{sep}env{sep}base64[.expiry][.checksum]`
    ///
    /// # Security
    ///
    /// Pre-allocates exact capacity to prevent reallocations during append operations.
    /// `Vec::append()` can trigger reallocation if capacity is insufficient, which would
    /// leave the old buffer (containing sensitive key material) in memory without zeroing.
    /// By allocating the exact capacity needed upfront, we ensure a single buffer is used
    /// throughout, which then gets moved to `SecureString` for proper zeroization on drop.
    fn assemble_key(
        &self,
        mut encoded: Zeroizing<Vec<u8>>,
        environment: Environment,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<SecureString> {
        let sep: &'static str = self.config.separator().into();
        let env: &'static str = environment.into();
        let version_component = self.config.version().component();

        let checksum_len = *self.config.checksum_length();
        let checksum_capacity = if checksum_len == 0 {
            0
        } else {
            checksum_len + 1
        };

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
            + checksum_capacity;

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

        // Compute checksum on the key body BEFORE appending expiry and checksum.
        // The expiry bytes are passed separately to checksum::compute() so the
        // checksum covers both key body and expiry without mutating the key buffer.
        let exp_bytes = exp_string.as_ref().map(|v| v.as_bytes());
        let computed_checksum = if checksum_len > 0 {
            Some(checksum::compute(
                &key,
                exp_bytes,
                self.config.checksum_algorithm(),
                checksum_len,
            ))
        } else {
            None
        };

        if let Some(b) = exp_bytes {
            key.push(CHECKSUM_SEPARATOR);
            key.extend_from_slice(b);
        }

        if let Some(cs) = computed_checksum {
            key.push(CHECKSUM_SEPARATOR);
            key.append(&mut cs.into_bytes());
        }

        // ZERO-COPY: Move the Vec<u8> directly into SecretBox<[u8]>.
        // No intermediate String allocation or UTF-8 validation needed.
        // The key bytes are guaranteed to be valid ASCII (prefix + base64url + hex checksum).
        Ok(SecureString::from(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureStringExt;

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
        assert!(key.as_str().starts_with("sk-live-"));

        // Verify key contains checksum separated by dot (enabled by default)
        assert!(
            key.as_str().contains('.'),
            "Should have checksum separated by dot"
        );

        // Split on . to separate checksum
        let parts: Vec<&str> = key.as_str().rsplitn(2, '.').collect();
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
}
