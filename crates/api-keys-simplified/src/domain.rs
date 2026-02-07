use crate::error::InitError;
use crate::validator::KeyStatus;
use crate::{
    config::{Environment, KeyConfig, KeyPrefix},
    error::Result,
    generator::KeyGenerator,
    hasher::KeyHasher,
    secure::SecureString,
    validator::KeyValidator,
    ExposeSecret, HashConfig,
};
use chrono::{DateTime, Utc};
use derive_getters::Getters;
use std::fmt::Debug;

/// ApiKeyManager is storable object
/// used to generate and verify API keys.
/// It contains immutable config data necessary
/// to operate. It does NOT contain ANY sensitive
/// data.
#[derive(Clone, Getters)]
pub struct ApiKeyManagerV0 {
    #[getter(skip)]
    generator: KeyGenerator,
    hasher: KeyHasher,
    #[getter(skip)]
    validator: KeyValidator,
    #[getter(skip)]
    include_checksum: bool,
    #[getter(skip)]
    expiry_grace_period: std::time::Duration,
}

// FIXME: Need better naming
/// Contains the Argon2 hash in PHC format and a stable key identifier.
///
/// The hash can be safely stored in your database without special security measures
/// since it's already cryptographically hashed. However, avoid unnecessary cloning
/// or logging to minimize exposure.
///
/// # Fields
///
/// - `key_id`: A stable, deterministic identifier derived from the API key itself.
///   This ID never changes for the same key, making it perfect for database indexing
///   and key lookups. Format: 32 hex characters (16 bytes of BLAKE3 hash).
///
/// - `hash`: The Argon2id hash in PHC format. This changes each time you hash the
///   same key (due to random salt), but the key_id remains constant.
///
/// # PHC Format
///
/// The hash is stored in PHC (Password Hashing Competition) format which includes:
/// - Algorithm identifier (argon2id)
/// - Version
/// - Parameters (memory cost, time cost, parallelism)
/// - Salt (base64-encoded, embedded in the hash string)
/// - Hash output (base64-encoded)
///
/// Example: `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`
///
/// The salt is embedded within the PHC string and can be extracted if needed using
/// the `password_hash` crate's `PasswordHash::new()` method.
///
/// # Key ID vs Hash
///
/// - **Key ID**: Stable identifier, never changes for the same key
/// - **Hash**: Changes each time you hash (due to different random salts)
///
/// Both fields can be accessed using the auto-generated getter methods `key_id()` and `hash()`
/// provided by the `Getters` derive macro.
#[derive(Debug, Getters, PartialEq)]
pub struct Hash {
    key_id: String,
    hash: String,
}

#[derive(Debug)]
pub struct NoHash;

/// Represents a generated API key with its hash.
///
/// The key field is stored in a `SecureString` which automatically zeros
/// its memory on drop, preventing potential memory disclosure.
#[derive(Debug)]
pub struct ApiKey<Hash> {
    key: SecureString,
    hash: Hash,
}

impl ApiKeyManagerV0 {
    pub fn init(
        prefix: impl Into<String>,
        config: KeyConfig,
        hash_config: HashConfig,
        expiry_grace_period: std::time::Duration,
    ) -> std::result::Result<Self, InitError> {
        let include_checksum = *config.checksum_length() != 0;
        let prefix = KeyPrefix::new(prefix)?;
        let generator = KeyGenerator::new(prefix, config)?;
        let hasher = KeyHasher::new(hash_config);

        // Generate dummy key and its hash for timing attack protection
        let dummy_key = generator.dummy_key().clone();
        let (_dummy_key_id, dummy_hash) = hasher.hash(&dummy_key)?;

        let validator = KeyValidator::new(include_checksum, dummy_key, dummy_hash)?;

        Ok(Self {
            generator,
            hasher,
            validator,
            include_checksum,
            expiry_grace_period,
        })
    }

    pub fn init_default_config(prefix: impl Into<String>) -> std::result::Result<Self, InitError> {
        Self::init(
            prefix,
            KeyConfig::default(),
            HashConfig::default(),
            std::time::Duration::from_secs(10),
        )
    }
    pub fn init_high_security_config(
        prefix: impl Into<String>,
    ) -> std::result::Result<Self, InitError> {
        Self::init(
            prefix,
            KeyConfig::high_security(),
            HashConfig::high_security(),
            std::time::Duration::from_secs(10),
        )
    }

    /// Generates a new API key for the specified environment.
    ///
    /// The generated key includes a checksum (if enabled) for fast DoS protection.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// let key = manager.generate(Environment::production())?;
    /// println!("Key: {}", key.key().expose_secret());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(&self, environment: impl Into<Environment>) -> Result<ApiKey<Hash>> {
        let key = self.generator.generate(environment.into(), None)?;
        let api_key = ApiKey::new(key).into_hashed(&self.hasher)?;

        Ok(api_key)
    }

    /// Generates a new API key with an expiration timestamp.
    ///
    /// The expiration is embedded in the key itself, making it stateless.
    /// Keys are automatically rejected after the expiry time without database lookups.
    ///
    /// # Use Cases
    ///
    /// - Trial keys (7-30 days)
    /// - Temporary partner access
    /// - Time-limited API access
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment};
    /// # use chrono::{Utc, Duration};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// // Create a 7-day trial key
    /// let expiry = Utc::now() + Duration::days(7);
    /// let key = manager.generate_with_expiry(Environment::production(), expiry)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_with_expiry(
        &self,
        environment: impl Into<Environment>,
        expiry: DateTime<Utc>,
    ) -> Result<ApiKey<Hash>> {
        let key = self.generator.generate(environment.into(), Some(expiry))?;
        let api_key = ApiKey::new(key).into_hashed(&self.hasher)?;

        Ok(api_key)
    }

    /// Verifies an API key against a stored hash.
    ///
    /// Returns `KeyStatus` indicating whether the key is valid or invalid.
    ///
    /// # Parameters
    ///
    /// * `key` - The API key to verify
    /// * `stored_hash` - The Argon2 hash stored in your database
    /// * `expiry_grace_period` - Optional grace period duration after expiry.
    ///   - `None`: Skip expiry validation (all keys treated as non-expired)
    ///   - `Some(Duration::ZERO)`: Strict expiry check (no grace period)
    ///   - `Some(duration)`: Key remains valid for `duration` after its expiry time
    ///
    /// The grace period protects against clock skew issues. Once a key expires beyond
    /// the grace period, it stays expired even if the system clock goes backwards.
    ///
    /// # Security Flow
    ///
    /// 1. **Checksum validation** (if enabled): Rejects invalid keys in ~20μs
    /// 2. **Argon2 verification**: Verifies hash for valid checksums (~300ms)
    /// 3. **Expiry check**: Returns `Invalid` if expired beyond grace period
    ///
    /// # Returns
    ///
    /// - `KeyStatus::Valid` - Key is valid and not expired
    /// - `KeyStatus::Invalid` - Key is invalid (wrong key, hash mismatch, checksum failed, or expired)
    ///
    /// # Note on Revocation
    ///
    /// This method does NOT check revocation status. To implement key revocation:
    /// 1. Mark the hash as revoked in your database
    /// 2. Check revocation status before calling this method
    /// 3. Only call `verify()` for non-revoked hashes
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, KeyStatus};
    /// # use std::time::Duration;
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let key = manager.generate(Environment::production()).unwrap();
    /// match manager.verify(key.key(), key.expose_hash().hash())? {
    ///     KeyStatus::Valid => { /* grant access */ },
    ///     KeyStatus::Invalid => { /* reject - wrong key or expired */ },
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn verify(&self, key: &SecureString, stored_hash: impl AsRef<str>) -> Result<KeyStatus> {
        if self.include_checksum && !self.verify_checksum(key)? {
            return Ok(KeyStatus::Invalid);
        }

        self.validator.verify(
            key.expose_secret(),
            stored_hash.as_ref(),
            self.expiry_grace_period,
        )
    }

    pub fn verify_checksum(&self, key: &SecureString) -> Result<bool> {
        self.generator.verify_checksum(key)
    }

    /// Extracts a stable key ID from an API key.
    ///
    /// This generates a deterministic identifier from the API key using BLAKE3 hash.
    /// The same key will always produce the same key ID, making it perfect for:
    /// - Database lookups and indexing
    /// - Key identification without exposing the full key
    /// - Tracking key usage across hash rotations
    ///
    /// # Format
    ///
    /// Returns a 32-character hex string (16 bytes / 128 bits of BLAKE3 hash).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, SecureString};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// // Extract key ID from an incoming API key (e.g., from Authorization header)
    /// let provided_key = SecureString::from("sk-live-abc123def456...".to_string());
    /// let key_id = manager.extract_key_id(&provided_key);
    ///
    /// // Use key_id for fast database lookup
    /// // let stored_hash = database.find_by_key_id(&key_id)?;
    /// // manager.verify(&provided_key, &stored_hash)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Security Note
    ///
    /// While the key ID is a one-way hash, it still uniquely identifies a key.
    /// Treat it as sensitive data and don't expose it in public APIs or logs.
    pub fn extract_key_id(&self, key: &SecureString) -> String {
        self.hasher.generate_key_id(key)
    }
}

impl<T> ApiKey<T> {
    /// Returns a reference to the secure API key.
    ///
    /// To access the underlying string, use `.expose_secret()` on the returned `SecureString`:
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret};
    /// # let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let api_key = generator.generate(Environment::production()).unwrap();
    /// let key_str: &str = api_key.key().expose_secret();
    /// ```
    ///
    /// # Security Note
    ///
    /// The key is stored in secure memory that is automatically zeroed on drop.
    /// Be careful NOT to clone or log the value unnecessarily.
    pub fn key(&self) -> &SecureString {
        &self.key
    }
}

impl ApiKey<NoHash> {
    /// Creates a new API key without a hash.
    ///
    /// This is typically used internally before converting to a hashed key.
    pub fn new(key: SecureString) -> ApiKey<NoHash> {
        ApiKey { key, hash: NoHash }
    }

    /// Converts this unhashed key into a hashed key by generating a new random salt
    /// and computing the Argon2 hash.
    ///
    /// This method is automatically called by `ApiKeyManagerV0::generate()` and
    /// `ApiKeyManagerV0::generate_with_expiry()`.
    pub fn into_hashed(self, hasher: &KeyHasher) -> Result<ApiKey<Hash>> {
        let (key_id, hash) = hasher.hash(&self.key)?;

        Ok(ApiKey {
            key: self.key,
            hash: Hash { key_id, hash },
        })
    }

    /// Converts this unhashed key into a hashed key using a specific PHC hash string.
    ///
    /// This is useful when you need to regenerate the same hash from the same key,
    /// for example in testing or when verifying hash consistency. The salt is extracted
    /// from the provided PHC hash string, and the key ID is derived from the key itself.
    ///
    /// # Parameters
    ///
    /// * `hasher` - The key hasher to use
    /// * `phc_hash` - An existing PHC-formatted hash string to extract the salt from
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment, ExposeSecret};
    /// # use api_keys_simplified::{SecureString, ApiKey};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// let key1 = manager.generate(Environment::production()).unwrap();
    ///
    /// // Regenerate hash with the same salt (extracted from the PHC hash)
    /// let key2 = ApiKey::new(SecureString::from(key1.key().expose_secret()))
    ///     .into_hashed_with_phc(manager.hasher(), key1.expose_hash().hash())
    ///     .unwrap();
    ///
    /// // Both hashes should be identical
    /// assert_eq!(key1.expose_hash(), key2.expose_hash());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_hashed_with_phc(self, hasher: &KeyHasher, phc_hash: &str) -> Result<ApiKey<Hash>> {
        let (key_id, hash) = hasher.hash_with_phc(&self.key, phc_hash)?;

        Ok(ApiKey {
            key: self.key,
            hash: Hash { key_id, hash },
        })
    }

    /// Consumes the API key and returns the underlying secure string.
    pub fn into_key(self) -> SecureString {
        self.key
    }
}

impl ApiKey<Hash> {
    /// Returns a reference to the hash.
    ///
    /// The returned `Hash` struct contains the Argon2 hash string in PHC format.
    /// The PHC format embeds all necessary information including the salt, algorithm
    /// parameters, and hash output. This single string should be stored in your
    /// database for later verification.
    ///
    /// # Accessing Fields
    ///
    /// Use the auto-generated getter method:
    /// - `.hash()` - Returns the PHC-formatted hash string as `&str`
    ///
    /// # PHC Format
    ///
    /// The hash string follows the PHC format:
    /// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`
    ///
    /// The salt is embedded in the hash string and can be extracted if needed using
    /// the `password_hash` crate's `PasswordHash::new()` method.
    ///
    /// # Security Note
    ///
    /// Although it's safe to store the hash, avoid making unnecessary clones
    /// or logging the hash to minimize exposure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use api_keys_simplified::{ApiKeyManagerV0, Environment};
    /// # let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    /// # let api_key = manager.generate(Environment::production()).unwrap();
    /// // Get the hash for storage
    /// let hash_struct = api_key.expose_hash();
    ///
    /// // Access the hash string for database storage
    /// let hash_str: &str = hash_struct.hash();
    /// println!("Store this hash: {}", hash_str);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn expose_hash(&self) -> &Hash {
        &self.hash
    }

    /// Consumes the API key and returns the underlying secure string.
    pub fn into_key(self) -> SecureString {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExposeSecret, SecureStringExt};

    #[test]
    fn test_full_lifecycle() {
        let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
        let api_key = generator.generate(Environment::production()).unwrap();

        let key_str = api_key.key();
        let hash_str = api_key.expose_hash().hash();

        assert!(key_str.expose_secret().starts_with("sk-live-"));
        assert!(hash_str.starts_with("$argon2id$"));

        assert_eq!(
            generator.verify(key_str, hash_str).unwrap(),
            KeyStatus::Valid
        );
        let wrong_key = SecureString::from("wrong_key".to_string());
        assert_eq!(
            generator.verify(&wrong_key, hash_str).unwrap(),
            KeyStatus::Invalid
        );
    }

    #[test]
    fn test_different_presets() {
        let balanced_gen = ApiKeyManagerV0::init_default_config("pk").unwrap();
        let balanced = balanced_gen.generate(Environment::test()).unwrap();

        let high_sec_gen = ApiKeyManagerV0::init_high_security_config("sk").unwrap();
        let high_sec = high_sec_gen.generate(Environment::Production).unwrap();

        assert!(!balanced.key().is_empty());
        assert!(high_sec.key().len() > balanced.key().len());
    }

    #[test]
    fn test_custom_config() {
        let config = KeyConfig::new().with_entropy(32).unwrap();

        let generator = ApiKeyManagerV0::init(
            "custom",
            config,
            HashConfig::default(),
            std::time::Duration::ZERO,
        )
        .unwrap();
        let key = generator.generate(Environment::production()).unwrap();
        assert!(generator.verify_checksum(key.key()).unwrap());
    }

    #[test]
    fn compare_hash() {
        let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
        let key = manager.generate(Environment::production()).unwrap();
        let new_secret = ApiKey::new(SecureString::from(key.key().expose_secret()))
            .into_hashed_with_phc(manager.hasher(), key.expose_hash().hash())
            .unwrap();

        assert_eq!(new_secret.expose_hash(), key.expose_hash());
    }
}
