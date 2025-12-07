use crate::error::ConfigError;
use derive_getters::Getters;
use lazy_static::lazy_static;
use regex::Regex;
use strum::{Display, EnumIter, EnumString};
use strum::{IntoEnumIterator, IntoStaticStr};

/// Key version for backward compatibility and migration.
/// Allows different key formats to coexist during transitions.
///
/// Version 0 represents no explicit version (backward compatible with existing keys).
/// Format: prefix{sep}env{sep}base64[.checksum]
///
/// Versions 1+ will have version between prefix and environment:
/// Format: prefix{sep}v{N}{sep}env{sep}base64[.checksum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyVersion(u32);

impl KeyVersion {
    /// No version in key
    /// Format: prefix-env-data.checksum
    pub const NONE: Self = KeyVersion(0);

    /// Version 1 - First versioned format
    /// Format: prefix-v1-env-data.checksum
    pub const V1: Self = KeyVersion(1);

    /// Version 2
    /// Format: prefix-v2-env-data.checksum
    pub const V2: Self = KeyVersion(2);

    /// Creates a new key version with the given number
    pub const fn new(version: u32) -> Self {
        KeyVersion(version)
    }

    /// Returns the version number
    pub const fn number(&self) -> u32 {
        self.0
    }

    /// Returns true if this version should be included in the key
    pub const fn is_versioned(&self) -> bool {
        self.0 > 0
    }

    /// Returns the version component string for key generation
    /// Returns empty string for version 0 (backward compatibility)
    pub fn component(&self) -> String {
        if self.0 == 0 {
            String::new()
        } else {
            format!("v{}", self.0)
        }
    }
}

impl Default for KeyVersion {
    fn default() -> Self {
        KeyVersion::NONE
    }
}

impl std::fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            write!(f, "unversioned")
        } else {
            write!(f, "v{}", self.0)
        }
    }
}

/// Deployment environment for API keys (dev/test/staging/live).
/// Used to visually distinguish keys across different environments and prevent accidental misuse
/// And allow users to set different Rate limits based on Environment.
#[derive(Debug, Clone, PartialEq, Eq, EnumIter, EnumString, Display, IntoStaticStr)]
pub enum Environment {
    #[strum(serialize = "dev")]
    Development,
    #[strum(serialize = "test")]
    Test,
    #[strum(serialize = "staging")]
    Staging,
    #[strum(serialize = "live")]
    Production,
}

lazy_static! {
    static ref ENVIRONMENT_VARIANTS: Vec<Environment> = Environment::iter().collect();
    // Regex to detect version patterns: 'v' followed by one or more digits
    static ref VERSION_PATTERN: Regex = Regex::new(r"v\d+").unwrap();
}

impl Environment {
    pub fn dev() -> Self {
        Environment::Development
    }
    pub fn test() -> Self {
        Environment::Test
    }
    pub fn staging() -> Self {
        Environment::Staging
    }
    pub fn production() -> Self {
        Environment::Production
    }
    pub fn variants() -> &'static [Environment] {
        &ENVIRONMENT_VARIANTS
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix(String);

impl KeyPrefix {
    pub fn new(prefix: impl Into<String>) -> std::result::Result<Self, ConfigError> {
        let prefix = prefix.into();
        if prefix.is_empty() || prefix.len() > 20 {
            return Err(ConfigError::InvalidPrefixLength);
        }
        if !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(ConfigError::InvalidPrefixCharacters);
        }
        if let Some(invalid) = Environment::variants().iter().find(|v| {
            let s: &'static str = (*v).into();
            prefix.contains(s)
        }) {
            return Err(ConfigError::InvalidPrefixSubstring(invalid.to_string()));
        }

        // Prevent prefixes that contain version patterns (e.g., "v1", "v2", "apiv42", "myv1key")
        // This would conflict with the version component in the key format
        if VERSION_PATTERN.is_match(&prefix) {
            return Err(ConfigError::InvalidPrefixVersionLike);
        }

        Ok(Self(prefix))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Separator character for API key components (prefix, environment and data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, IntoStaticStr, Default)]
pub enum Separator {
    #[strum(serialize = "/")]
    Slash,

    #[strum(serialize = "-")]
    #[default]
    Dash,

    #[strum(serialize = "~")]
    Tilde,
}

#[derive(Debug, Clone, Getters)]
pub struct HashConfig {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl HashConfig {
    /// Creates a custom HashConfig with validated parameters.
    pub fn custom(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    ) -> std::result::Result<Self, ConfigError> {
        // Verify parameters are accepted by Argon2 library
        // Bad idea to do it here.. but we'll keep it here for now
        argon2::Params::new(memory_cost, time_cost, parallelism, None)
            .map_err(|_| ConfigError::InvalidHashParams)?;

        Ok(Self {
            memory_cost,
            time_cost,
            parallelism,
        })
    }

    /// Balanced preset for general production use.
    ///
    /// - Memory: 46 MB
    /// - Time: 1 iterations
    /// - Parallelism: 1 threads
    ///   Default recommendation according to
    ///   [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
    ///   Refer the document for best practices at different memory cost.
    pub fn balanced() -> Self {
        Self {
            memory_cost: 47_104,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// High security preset for sensitive operations.
    ///
    /// - Memory: 64 MB
    /// - Time: 2 iterations
    /// - Parallelism: 4 threads
    ///   Higher limits then what's suggested in
    ///   [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
    pub fn high_security() -> Self {
        Self {
            memory_cost: 65_536,
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl Default for HashConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

#[derive(Default, Debug, Clone, IntoStaticStr)]
pub enum ChecksumAlgo {
    /// Cryptographic yet fast
    /// hashing algo, suitable for
    /// quick checksum verification.
    #[default]
    #[strum(serialize = "b3")]
    Black3,
}

#[derive(Debug, Clone, Getters)]
pub struct KeyConfig {
    entropy_bytes: usize,
    checksum_length: usize,
    separator: Separator,
    checksum_algorithm: ChecksumAlgo,
    version: KeyVersion,
}

impl KeyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entropy(mut self, bytes: usize) -> std::result::Result<Self, ConfigError> {
        if bytes < 16 {
            return Err(ConfigError::EntropyTooLow);
        }
        if bytes > 64 {
            return Err(ConfigError::EntropyTooHigh);
        }
        self.entropy_bytes = bytes;
        Ok(self)
    }

    pub fn checksum(mut self, bytes: usize) -> Result<Self, ConfigError> {
        match &self.checksum_algorithm {
            ChecksumAlgo::Black3 => {
                if bytes < 32 {
                    return Err(ConfigError::ChecksumLenTooSmall);
                }
                if bytes > 64 {
                    return Err(ConfigError::ChecksumLenTooLarge);
                }
            }
        }
        self.checksum_length = bytes;
        Ok(self)
    }

    pub fn disable_checksum(mut self) -> Self {
        self.checksum_length = 0;
        self
    }

    pub fn with_separator(mut self, separator: Separator) -> Self {
        self.separator = separator;
        self
    }

    pub fn with_version(mut self, version: KeyVersion) -> Self {
        self.version = version;
        self
    }

    pub fn balanced() -> Self {
        Self {
            entropy_bytes: 24,
            checksum_length: 20,
            separator: Separator::default(),
            checksum_algorithm: ChecksumAlgo::default(),
            version: KeyVersion::default(),
        }
    }

    pub fn high_security() -> Self {
        Self {
            entropy_bytes: 64,
            checksum_length: 32,
            separator: Separator::default(),
            checksum_algorithm: ChecksumAlgo::default(),
            version: KeyVersion::default(),
        }
    }
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_prefix_validation() {
        assert!(KeyPrefix::new("sk").is_ok());
        assert!(KeyPrefix::new("api_key").is_ok());
        assert!(KeyPrefix::new("").is_err());
        assert!(KeyPrefix::new("invalid-prefix").is_err());
    }

    #[test]
    fn test_prefix_cannot_be_version_like() {
        // Should reject any prefix containing version patterns (v followed by digits)
        assert!(KeyPrefix::new("v1").is_err());
        assert!(KeyPrefix::new("v2").is_err());
        assert!(KeyPrefix::new("v42").is_err());
        assert!(KeyPrefix::new("v100").is_err());
        assert!(KeyPrefix::new("v0").is_err());
        assert!(KeyPrefix::new("apiv1").is_err());
        assert!(KeyPrefix::new("apiv2").is_err());
        assert!(KeyPrefix::new("myv42key").is_err());
        assert!(KeyPrefix::new("testv1").is_err());
        assert!(KeyPrefix::new("v1beta").is_err());
        assert!(KeyPrefix::new("betav1").is_err());
        assert!(KeyPrefix::new("keyv123end").is_err());

        // Should allow prefixes without version patterns
        assert!(KeyPrefix::new("version").is_ok());
        assert!(KeyPrefix::new("vault").is_ok());
        assert!(KeyPrefix::new("v_key").is_ok());
        assert!(KeyPrefix::new("vkey").is_ok());
        assert!(KeyPrefix::new("api").is_ok());
        assert!(KeyPrefix::new("sk").is_ok());
        assert!(KeyPrefix::new("versionkey").is_ok());
        assert!(KeyPrefix::new("apiversion").is_ok());
        // Edge case: just 'v' should be allowed
        assert!(KeyPrefix::new("v").is_ok());
    }

    #[test]
    fn test_config_validation() {
        assert!(KeyConfig::new().with_entropy(32).is_ok());
        assert!(KeyConfig::new().with_entropy(8).is_err());
        assert!(KeyConfig::new().with_entropy(128).is_err());
    }

    #[test]
    fn test_separator_display() {
        let slash: &'static str = Separator::Slash.into();
        let dash: &'static str = Separator::Dash.into();
        let tilde: &'static str = Separator::Tilde.into();
        assert_eq!(slash, "/");
        assert_eq!(dash, "-");
        assert_eq!(tilde, "~");
    }

    #[test]
    fn test_separator_from_str() {
        assert_eq!(Separator::from_str("/").unwrap(), Separator::Slash);
        assert_eq!(Separator::from_str("-").unwrap(), Separator::Dash);
        assert_eq!(Separator::from_str("~").unwrap(), Separator::Tilde);
        assert!(Separator::from_str(".").is_err());
    }

    #[test]
    fn test_separator_default() {
        assert_eq!(Separator::default(), Separator::Dash);
    }

    #[test]
    fn test_key_config_with_separator() {
        let config = KeyConfig::new().with_separator(Separator::Dash);
        assert_eq!(config.separator, Separator::Dash);

        let config = KeyConfig::new().with_separator(Separator::Tilde);
        assert_eq!(config.separator, Separator::Tilde);
    }
}
