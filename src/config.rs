use strum::{Display, EnumString};
use crate::error::{ConfigError, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyString(String);

impl TryFrom<&str> for NonEmptyString {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl TryFrom<String> for NonEmptyString {
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(ConfigError::EmptyString.into());
        }
        Ok(Self(value))
    }
}

impl NonEmptyString {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    Development,
    Test,
    Staging,
    Production,
    Custom(NonEmptyString),
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
    pub fn custom(name: NonEmptyString) -> Self {
        Self::Custom(name)
    }
}

impl Environment {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Development => "dev",
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "live",
            Self::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix(String);

impl KeyPrefix {
    pub fn new(prefix: impl Into<String>) -> Result<Self> {
        let prefix = prefix.into();
        if prefix.is_empty() || prefix.len() > 10 {
            return Err(ConfigError::InvalidPrefixLength.into());
        }
        if !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(ConfigError::InvalidPrefixCharacters.into());
        }
        Ok(Self(prefix))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for KeyPrefix {
    fn default() -> Self {
        Self("key".to_string())
    }
}


/// Separator character for API key components (prefix, environment and data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString)]
pub enum Separator {
    #[strum(serialize = "/")]
    Slash,

    #[strum(serialize = ".")]
    Dot,
    
    #[strum(serialize = "~")]
    Tilde,
}

impl Default for Separator {
    fn default() -> Self {
        Separator::Dot
    }
}


#[derive(Debug, Clone)]
pub struct HashConfig {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl HashConfig {
    pub fn balanced() -> Self {
        Self {
            memory_cost: 19_456,
            time_cost: 2,
            parallelism: 1,
        }
    }

    pub fn high_security() -> Self {
        Self {
            memory_cost: 65_536,
            time_cost: 3,
            parallelism: 4,
        }
    }

    pub fn fast() -> Self {
        Self {
            memory_cost: 8_192,
            time_cost: 1,
            parallelism: 1,
        }
    }
}

impl Default for HashConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub entropy_bytes: usize,
    pub include_checksum: bool,
    pub hash_config: HashConfig,
    pub separator: Separator,
}

impl KeyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entropy(mut self, bytes: usize) -> Result<Self> {
        if bytes < 16 {
            return Err(ConfigError::EntropyTooLow.into());
        }
        if bytes > 64 {
            return Err(ConfigError::EntropyTooHigh.into());
        }
        self.entropy_bytes = bytes;
        Ok(self)
    }

    pub fn with_checksum(mut self, include: bool) -> Self {
        self.include_checksum = include;
        self
    }

    pub fn with_hash_config(mut self, hash_config: HashConfig) -> Self {
        self.hash_config = hash_config;
        self
    }

    pub fn with_separator(mut self, separator: Separator) -> Self {
        self.separator = separator;
        self
    }

    pub fn balanced() -> Self {
        Self {
            entropy_bytes: 24,
            include_checksum: true,
            hash_config: HashConfig::balanced(),
            separator: Separator::default(),
        }
    }

    pub fn high_security() -> Self {
        Self {
            entropy_bytes: 32,
            include_checksum: true,
            hash_config: HashConfig::high_security(),
            separator: Separator::default(),
        }
    }

    pub fn fast() -> Self {
        Self {
            entropy_bytes: 24,
            include_checksum: false,
            hash_config: HashConfig::fast(),
            separator: Separator::default(),
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
    fn test_config_validation() {
        assert!(KeyConfig::new().with_entropy(32).is_ok());
        assert!(KeyConfig::new().with_entropy(8).is_err());
        assert!(KeyConfig::new().with_entropy(128).is_err());
    }

    #[test]
    fn test_separator_display() {
        assert_eq!(Separator::Slash.to_string(), "/");
        assert_eq!(Separator::Dot.to_string(), ".");
        assert_eq!(Separator::Tilde.to_string(), "~");
    }

    #[test]
    fn test_separator_from_str() {
        assert_eq!(Separator::from_str("/").unwrap(), Separator::Slash);
        assert_eq!(Separator::from_str(".").unwrap(), Separator::Dot);
        assert_eq!(Separator::from_str("~").unwrap(), Separator::Tilde);
        assert!(Separator::from_str("-").is_err());
    }

    #[test]
    fn test_separator_default() {
        assert_eq!(Separator::default(), Separator::Dot);
    }

    #[test]
    fn test_key_config_with_separator() {
        let config = KeyConfig::new()
            .with_separator(Separator::Dot);
        assert_eq!(config.separator, Separator::Dot);

        let config = KeyConfig::new()
            .with_separator(Separator::Tilde);
        assert_eq!(config.separator, Separator::Tilde);
    }
}
