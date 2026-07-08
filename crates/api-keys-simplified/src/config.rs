//! # Configuration layer (level 0)
//!
//! This is the base of the dependency tree. It defines every validated
//! primitive (`Environment`, `KeyVersion`, `KeyPrefix`, `Separator`,
//! `ChecksumAlgo`) plus the [`ConfigBuilder`] → [`ValidatedConfig`] flow.
//!
//! All configuration validation lives here and happens **once**, in
//! [`ConfigBuilder::build`]. Unlike a fail-on-first-error chain, `build` uses the
//! `tailcall-valid` applicative validator to accumulate **every** problem and
//! return them together as [`ConfigErrors`].
//!
//! Holding a [`ValidatedConfig`] is proof that the configuration is sound; the
//! generate / verify layers built on top of it cannot fail for config reasons.

use std::time::Duration;

use lazy_static::lazy_static;
use regex::Regex;
use strum::{Display, EnumIter, EnumString, IntoEnumIterator, IntoStaticStr};
use tailcall_valid::{Cause, Valid, Validator};

use crate::shared::secure::SecureString;

lazy_static! {
    static ref ENVIRONMENT_VARIANTS: Vec<Environment> = Environment::iter().collect();
    // Regex to detect version patterns: 'v' followed by one or more digits.
    static ref VERSION_PATTERN: Regex = Regex::new(r"v\d+").unwrap();
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Key version for backward compatibility and migration.
///
/// Version 0 (`NONE`) produces an unversioned key: `prefix{sep}env{sep}data`.
/// Versions 1+ embed `vN` between prefix and environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyVersion(u32);

impl KeyVersion {
    /// No version in the key.
    pub const NONE: Self = KeyVersion(0);
    /// Version 1 — first versioned format.
    pub const V1: Self = KeyVersion(1);
    /// Version 2.
    pub const V2: Self = KeyVersion(2);

    pub const fn new(version: u32) -> Self {
        KeyVersion(version)
    }

    pub const fn number(&self) -> u32 {
        self.0
    }

    pub const fn is_versioned(&self) -> bool {
        self.0 > 0
    }

    /// The `vN` component string, or empty for version 0.
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

/// Deployment environment for API keys.
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

/// Separator character for API key components.
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

/// Checksum algorithm used for fast integrity / DoS-protection checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, IntoStaticStr)]
pub enum ChecksumAlgo {
    #[default]
    #[strum(serialize = "b3")]
    Blake3,
}

/// A prefix that has passed every validation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix(String);

impl KeyPrefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated checksum specification (algorithm + output length in hex chars).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumSpec {
    pub algo: ChecksumAlgo,
    pub length: usize,
}

/// Argon2id cost parameters (memory in KiB, iteration count, and lanes).
///
/// Only relevant when the chosen [`HashAlgo`] is [`HashAlgo::Argon2id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// Balanced preset (OWASP-recommended default): 46 MB, t=1, p=1.
    pub const fn balanced() -> Self {
        Self {
            memory_cost: 47_104,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// High-security preset: 64 MB, t=3, p=4.
    pub const fn high_security() -> Self {
        Self {
            memory_cost: 65_536,
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Storage-hash strategy applied to a key before it is persisted.
///
/// API keys generated by this crate are high-entropy (>=128-bit) random values.
/// Per NIST SP 800-63B, such "look-up secrets" only require an *approved fast
/// hash* for storage — the slow, memory-hard password hashers (Argon2/bcrypt)
/// are mandated only for low-entropy secrets like passwords. Accordingly:
///
/// - [`HashAlgo::Sha256`] — fast, unkeyed. Fine for high-entropy keys.
/// - [`HashAlgo::HmacSha256`] — fast, **keyed** with a server-side pepper.
///   Recommended: a leaked key database alone cannot be used to verify keys.
/// - [`HashAlgo::Argon2id`] — slow, memory-hard. Opt-in for belt-and-suspenders
///   or when hashing lower-entropy inputs.
///
/// The pepper in [`HashAlgo::HmacSha256`] MUST be stored separately from the key
/// database (environment variable, secrets manager, or HSM), never alongside the
/// hashes.
#[derive(Clone)]
pub enum HashAlgo {
    /// Fast SHA-256 digest of the key. Suitable for high-entropy keys.
    Sha256,
    /// Keyed HMAC-SHA256 with a server-side pepper (recommended).
    HmacSha256 { pepper: SecureString },
    /// Slow, memory-hard Argon2id. Opt-in.
    Argon2id(Argon2Params),
}

impl std::fmt::Debug for HashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SECURITY: never print the pepper.
        match self {
            HashAlgo::Sha256 => write!(f, "Sha256"),
            HashAlgo::HmacSha256 { .. } => write!(f, "HmacSha256 {{ pepper: <redacted> }}"),
            HashAlgo::Argon2id(p) => write!(f, "Argon2id({p:?})"),
        }
    }
}

/// A fully validated, immutable configuration.
///
/// The generate and verify layers consume this by shared reference. It is cheap
/// to clone. Note: if the configured [`HashAlgo`] is [`HashAlgo::HmacSha256`], it
/// holds a secret pepper (kept in a [`SecureString`]); avoid logging it.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    prefix: KeyPrefix,
    version: KeyVersion,
    separator: Separator,
    entropy_bytes: usize,
    checksum: Option<ChecksumSpec>,
    hash: HashAlgo,
    grace_period: Duration,
}

impl ValidatedConfig {
    pub fn prefix(&self) -> &KeyPrefix {
        &self.prefix
    }
    pub fn version(&self) -> KeyVersion {
        self.version
    }
    pub fn separator(&self) -> Separator {
        self.separator
    }
    pub fn entropy_bytes(&self) -> usize {
        self.entropy_bytes
    }
    pub fn checksum(&self) -> Option<ChecksumSpec> {
        self.checksum
    }
    pub fn hash(&self) -> &HashAlgo {
        &self.hash
    }
    pub fn grace_period(&self) -> Duration {
        self.grace_period
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Trace context attached to each accumulated error: the config field name.
pub type Field = &'static str;

/// A validation producing `A`, accumulating [`ConfigError`]s tagged by [`Field`].
type Vc<A> = Valid<A, ConfigError, Field>;

/// A single configuration problem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("prefix is required")]
    MissingPrefix,

    #[error("prefix must be between 1 and 20 characters")]
    InvalidPrefixLength,

    #[error("prefix must contain only alphanumeric characters, '_' or '-'")]
    InvalidPrefixCharacters,

    #[error("prefix must not contain the reserved environment substring '{0}'")]
    InvalidPrefixSubstring(&'static str),

    #[error("prefix cannot look like a version number (e.g. 'v1', 'v2', 'v42')")]
    InvalidPrefixVersionLike,

    #[error("entropy must be at least 16 bytes (128 bits)")]
    EntropyTooLow,

    #[error("entropy cannot exceed 64 bytes (512 bits)")]
    EntropyTooHigh,

    #[error("BLAKE3 checksum length must be at least 32")]
    ChecksumLenTooSmall,

    #[error("BLAKE3 checksum length must be at most 64")]
    ChecksumLenTooLarge,

    #[error("invalid Argon2 parameters")]
    InvalidHashParams,

    #[error("HMAC pepper must not be empty")]
    EmptyPepper,
}

/// Aggregated, user-facing error returned by [`ConfigBuilder::build`].
///
/// Wraps the flat list of every [`ConfigError`] detected, so callers can fix
/// them all in one pass rather than fix-one-recompile-repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors(Vec<ConfigError>);

impl ConfigErrors {
    fn from_causes(causes: Vec<Cause<ConfigError, Field>>) -> Self {
        ConfigErrors(causes.into_iter().map(|c| c.error).collect())
    }

    /// The individual problems, in the order they were detected.
    pub fn errors(&self) -> &[ConfigError] {
        &self.0
    }
}

impl std::fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "configuration invalid ({} error(s)):", self.0.len())?;
        for e in &self.0 {
            writeln!(f, "  - {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Reserved environment substrings a prefix may not contain.
const RESERVED_ENV_SUBSTRINGS: &[&str] = &["dev", "test", "staging", "live"];

/// Collects raw, unvalidated configuration intent.
///
/// Every setter is infallible; all validation is deferred to
/// [`ConfigBuilder::build`], which reports every problem at once.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    prefix: Option<String>,
    version: KeyVersion,
    separator: Separator,
    entropy_bytes: usize,
    checksum_enabled: bool,
    checksum_algo: ChecksumAlgo,
    checksum_length: usize,
    hash: HashAlgo,
    grace_period: Duration,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            prefix: None,
            version: KeyVersion::NONE,
            separator: Separator::Dash,
            entropy_bytes: 24,
            checksum_enabled: true,
            checksum_algo: ChecksumAlgo::Blake3,
            checksum_length: 32,
            // NOTE: the default hash algorithm is flipped to Sha256 in a later
            // step (A5); Argon2id is kept here for now to preserve behavior.
            hash: HashAlgo::Argon2id(Argon2Params::balanced()),
            grace_period: Duration::from_secs(10),
        }
    }
}

impl ConfigBuilder {
    /// A builder pre-populated with balanced defaults. Set at least a prefix.
    pub fn new() -> Self {
        Self::default()
    }

    /// A builder pre-populated with high-security defaults (64-byte entropy,
    /// larger checksum, and slow Argon2id hashing with stronger params).
    pub fn high_security() -> Self {
        Self {
            entropy_bytes: 64,
            checksum_length: 64,
            hash: HashAlgo::Argon2id(Argon2Params::high_security()),
            ..Self::default()
        }
    }

    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn version(mut self, version: KeyVersion) -> Self {
        self.version = version;
        self
    }

    pub fn separator(mut self, separator: Separator) -> Self {
        self.separator = separator;
        self
    }

    pub fn entropy(mut self, bytes: usize) -> Self {
        self.entropy_bytes = bytes;
        self
    }

    pub fn checksum(mut self, algo: ChecksumAlgo, length: usize) -> Self {
        self.checksum_enabled = true;
        self.checksum_algo = algo;
        self.checksum_length = length;
        self
    }

    pub fn no_checksum(mut self) -> Self {
        self.checksum_enabled = false;
        self
    }

    /// Select the storage-hash strategy. See [`HashAlgo`].
    ///
    /// Default is [`HashAlgo::Argon2id`] with balanced parameters (this default
    /// is flipped to [`HashAlgo::Sha256`] in a later step).
    pub fn hash(mut self, algo: HashAlgo) -> Self {
        self.hash = algo;
        self
    }

    pub fn grace_period(mut self, grace_period: Duration) -> Self {
        self.grace_period = grace_period;
        self
    }

    /// Validate every field and assemble a [`ValidatedConfig`].
    ///
    /// Does **not** stop at the first bad field: `fuse` runs every validator and
    /// merges their causes, so the returned [`ConfigErrors`] lists all problems.
    pub fn build(self) -> Result<ValidatedConfig, ConfigErrors> {
        let version = self.version;
        let separator = self.separator;
        let grace_period = self.grace_period;

        let prefix = validate_prefix(self.prefix);
        let entropy = validate_entropy(self.entropy_bytes);
        let checksum = validate_checksum(
            self.checksum_enabled,
            self.checksum_algo,
            self.checksum_length,
        );
        let hash = validate_hash(self.hash);

        // `fuse` appends via the `Append` trait, flattening into a single tuple:
        // (KeyPrefix, usize, Option<ChecksumSpec>, Argon2Params).
        prefix
            .fuse(entropy)
            .fuse(checksum)
            .fuse(hash)
            .map(|(prefix, entropy_bytes, checksum, hash)| ValidatedConfig {
                prefix,
                version,
                separator,
                entropy_bytes,
                checksum,
                hash,
                grace_period,
            })
            .to_result()
            .map_err(ConfigErrors::from_causes)
    }
}

// ---------------------------------------------------------------------------
// Field validators
// ---------------------------------------------------------------------------

fn validate_prefix(raw: Option<String>) -> Vc<KeyPrefix> {
    let prefix = match raw {
        Some(p) => p,
        None => return Valid::fail(ConfigError::MissingPrefix).trace("prefix"),
    };

    let length: Vc<()> = Valid::<(), _, _>::fail(ConfigError::InvalidPrefixLength)
        .when(|| prefix.is_empty() || prefix.len() > 20);

    let chars: Vc<()> = Valid::<(), _, _>::fail(ConfigError::InvalidPrefixCharacters).when(|| {
        !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    });

    let substring: Vc<()> = match RESERVED_ENV_SUBSTRINGS
        .iter()
        .find(|s| prefix.contains(**s))
    {
        Some(reserved) => Valid::fail(ConfigError::InvalidPrefixSubstring(reserved)),
        None => Valid::succeed(()),
    };

    let version_like: Vc<()> = Valid::<(), _, _>::fail(ConfigError::InvalidPrefixVersionLike)
        .when(|| VERSION_PATTERN.is_match(&prefix));

    length
        .fuse(chars)
        .fuse(substring)
        .fuse(version_like)
        .map_to(KeyPrefix(prefix))
        .trace("prefix")
}

fn validate_entropy(bytes: usize) -> Vc<usize> {
    if bytes < 16 {
        Valid::fail(ConfigError::EntropyTooLow).trace("entropy")
    } else if bytes > 64 {
        Valid::fail(ConfigError::EntropyTooHigh).trace("entropy")
    } else {
        Valid::succeed(bytes)
    }
}

fn validate_checksum(enabled: bool, algo: ChecksumAlgo, length: usize) -> Vc<Option<ChecksumSpec>> {
    if !enabled {
        return Valid::succeed(None);
    }

    match algo {
        ChecksumAlgo::Blake3 => {
            if length < 32 {
                Valid::fail(ConfigError::ChecksumLenTooSmall).trace("checksum")
            } else if length > 64 {
                Valid::fail(ConfigError::ChecksumLenTooLarge).trace("checksum")
            } else {
                Valid::succeed(Some(ChecksumSpec { algo, length }))
            }
        }
    }
}

fn validate_hash(hash: HashAlgo) -> Vc<HashAlgo> {
    match &hash {
        // A fast unkeyed hash has nothing to validate.
        HashAlgo::Sha256 => Valid::succeed(hash),

        // The HMAC pepper must be non-empty to provide any keying.
        HashAlgo::HmacSha256 { pepper } => {
            use crate::shared::secure::SecureStringExt;
            if pepper.is_empty() {
                Valid::fail(ConfigError::EmptyPepper).trace("hash")
            } else {
                Valid::succeed(hash)
            }
        }

        // Probe the Argon2 library for parameter validity here, in the config
        // layer, rather than deep inside the hasher.
        HashAlgo::Argon2id(p) => {
            match argon2::Params::new(p.memory_cost, p.time_cost, p.parallelism, None) {
                Ok(_) => Valid::succeed(hash),
                Err(_) => Valid::fail(ConfigError::InvalidHashParams).trace("hash"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn valid_default_config_builds() {
        let cfg = ConfigBuilder::new().prefix("sk").build().unwrap();
        assert_eq!(cfg.prefix().as_str(), "sk");
        assert_eq!(cfg.entropy_bytes(), 24);
        assert_eq!(cfg.checksum().unwrap().length, 32);
        assert_eq!(cfg.version(), KeyVersion::NONE);
    }

    #[test]
    fn missing_prefix_is_reported() {
        let err = ConfigBuilder::new().build().unwrap_err();
        assert_eq!(err.errors(), &[ConfigError::MissingPrefix]);
    }

    #[test]
    fn no_checksum_yields_none() {
        let cfg = ConfigBuilder::new()
            .prefix("sk")
            .no_checksum()
            .build()
            .unwrap();
        assert!(cfg.checksum().is_none());
    }

    #[test]
    fn all_errors_accumulate_across_fields() {
        let err = ConfigBuilder::new()
            .prefix("bad prefix")
            .entropy(4)
            .checksum(ChecksumAlgo::Blake3, 8)
            .hash(HashAlgo::Argon2id(Argon2Params {
                memory_cost: 0,
                time_cost: 0,
                parallelism: 0,
            }))
            .build()
            .unwrap_err();

        let errors = err.errors();
        assert!(errors.contains(&ConfigError::InvalidPrefixCharacters));
        assert!(errors.contains(&ConfigError::EntropyTooLow));
        assert!(errors.contains(&ConfigError::ChecksumLenTooSmall));
        assert!(errors.contains(&ConfigError::InvalidHashParams));
        assert!(errors.len() >= 4, "expected >= 4 errors, got {errors:?}");
    }

    #[test]
    fn hash_algos_build_and_validate() {
        // Sha256: always valid, no secret needed.
        assert!(ConfigBuilder::new()
            .prefix("sk")
            .hash(HashAlgo::Sha256)
            .build()
            .is_ok());

        // HmacSha256 with a non-empty pepper: valid.
        assert!(ConfigBuilder::new()
            .prefix("sk")
            .hash(HashAlgo::HmacSha256 {
                pepper: SecureString::from("pepper".to_string()),
            })
            .build()
            .is_ok());

        // HmacSha256 with an empty pepper: EmptyPepper error.
        let err = ConfigBuilder::new()
            .prefix("sk")
            .hash(HashAlgo::HmacSha256 {
                pepper: SecureString::from(String::new()),
            })
            .build()
            .unwrap_err();
        assert!(err.errors().contains(&ConfigError::EmptyPepper));
    }

    #[test]
    fn hash_algo_debug_redacts_pepper() {
        let algo = HashAlgo::HmacSha256 {
            pepper: SecureString::from("super-secret-pepper".to_string()),
        };
        let dbg = format!("{algo:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret-pepper"));
    }

    #[test]
    fn multiple_prefix_rules_accumulate() {
        let err = ConfigBuilder::new()
            .prefix("this-prefix-is-way-too-long-live")
            .build()
            .unwrap_err();

        let errors = err.errors();
        assert!(errors.contains(&ConfigError::InvalidPrefixLength));
        assert!(errors.contains(&ConfigError::InvalidPrefixSubstring("live")));
    }

    #[test]
    fn version_like_prefix_rejected() {
        let err = ConfigBuilder::new().prefix("apiv1").build().unwrap_err();
        assert!(err
            .errors()
            .contains(&ConfigError::InvalidPrefixVersionLike));
    }

    #[test]
    fn display_lists_every_error() {
        let err = ConfigBuilder::new()
            .prefix("live")
            .entropy(4)
            .build()
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("error(s)"));
        assert!(text.matches("  - ").count() >= 2, "rendered: {text}");
    }

    #[test]
    fn separator_roundtrip() {
        assert_eq!(Separator::from_str("/").unwrap(), Separator::Slash);
        assert_eq!(Separator::default(), Separator::Dash);
        let dash: &'static str = Separator::Dash.into();
        assert_eq!(dash, "-");
    }
}
