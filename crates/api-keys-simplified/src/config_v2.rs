//! # POC: Accumulating configuration validation
//!
//! This module is a **proof of concept** for the redesigned configuration layer
//! discussed in the architecture review. It demonstrates two ideas:
//!
//! 1. A single `ConfigBuilder` where the user declares prefix / version / algo /
//!    entropy / checksum / hash params, and **all** validation is deferred to one
//!    `build()` call.
//! 2. Using the [`tailcall_valid`] applicative validator so that `build()` reports
//!    **every** configuration problem at once instead of failing on the first one.
//!
//! It is intentionally self-contained (its own error enum, its own primitive
//! newtypes) so it can live alongside the current `config.rs` without disturbing
//! the shipping code. Nothing here is wired into `ApiKeyManagerV0` yet.
//!
//! ```
//! use api_keys_simplified::config_v2::{ConfigBuilder, ChecksumAlgo};
//!
//! // A config with SEVERAL problems reports all of them together.
//! let errors = ConfigBuilder::new()
//!     .prefix("this-prefix-is-way-too-long-and-also-live") // too long + contains "live"
//!     .entropy(4)                                          // below minimum
//!     .checksum(ChecksumAlgo::Blake3, 8)                   // below minimum
//!     .build()
//!     .unwrap_err();
//!
//! assert!(errors.errors().len() >= 3);
//! ```

use std::time::Duration;

use lazy_static::lazy_static;
use regex::Regex;
use tailcall_valid::{Cause, Valid, Validator};

lazy_static! {
    static ref VERSION_PATTERN: Regex = Regex::new(r"v\d+").unwrap();
}

/// Trace context attached to each accumulated error: the config field name.
pub type Field = &'static str;

/// A validation that yields `A`, accumulating [`ConfigError`]s tagged by [`Field`].
type Vc<A> = Valid<A, ConfigError, Field>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A single configuration problem. Mirrors the granular variants that exist in
/// today's `ConfigError`, minus the ones that are enforced structurally here.
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
}

/// Aggregated, user-facing error returned by [`ConfigBuilder::build`].
///
/// Wraps the flat list of every [`ConfigError`] that was detected, so callers
/// can fix them all in one pass rather than fix-one-recompile-repeat.
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
// Validated primitives (proof types)
// ---------------------------------------------------------------------------

/// A prefix that has passed every validation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix(String);

impl KeyPrefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reserved environment substrings a prefix may not contain.
const RESERVED_ENV_SUBSTRINGS: &[&str] = &["dev", "test", "staging", "live"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChecksumAlgo {
    #[default]
    Blake3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Separator {
    #[default]
    Dash,
    Slash,
    Tilde,
}

/// A checksum spec (algorithm + length) that has passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChecksumSpec {
    pub algo: ChecksumAlgo,
    pub length: usize,
}

/// Argon2 parameters that have passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashSpec {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

/// A fully validated, immutable configuration. Holding one is proof that the
/// config layer already rejected every invalid combination — construction of
/// the generator / verifier downstream cannot fail for config reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub prefix: KeyPrefix,
    pub version: u32,
    pub separator: Separator,
    pub entropy_bytes: usize,
    pub checksum: Option<ChecksumSpec>,
    pub hash: HashSpec,
    pub grace_period: Duration,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Collects raw, unvalidated user intent. All validation is deferred to
/// [`ConfigBuilder::build`], which reports every problem at once.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    prefix: Option<String>,
    version: u32,
    separator: Separator,
    entropy_bytes: usize,
    checksum_enabled: bool,
    checksum_algo: ChecksumAlgo,
    checksum_length: usize,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    grace_period: Duration,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        // "balanced" defaults, matching the current crate presets.
        Self {
            prefix: None,
            version: 0,
            separator: Separator::Dash,
            entropy_bytes: 24,
            checksum_enabled: true,
            checksum_algo: ChecksumAlgo::Blake3,
            // NOTE: the current `KeyConfig::balanced()` hardcodes 20 here, but its
            // own `checksum()` setter rejects anything < 32 — the presets bypass
            // their own validation. This POC keeps the default internally consistent.
            checksum_length: 32,
            memory_cost: 47_104,
            time_cost: 1,
            parallelism: 1,
            grace_period: Duration::from_secs(10),
        }
    }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn version(mut self, version: u32) -> Self {
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

    pub fn hash_params(mut self, memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        self.memory_cost = memory_cost;
        self.time_cost = time_cost;
        self.parallelism = parallelism;
        self
    }

    pub fn grace_period(mut self, grace_period: Duration) -> Self {
        self.grace_period = grace_period;
        self
    }

    /// Validate every field and assemble a [`ValidatedConfig`].
    ///
    /// Unlike the current `init`/`with_*` chain, this does **not** stop at the
    /// first bad field. `fuse` runs every validator and merges their `Cause`s,
    /// so the returned [`ConfigErrors`] lists all problems together.
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
        let hash = validate_hash(self.memory_cost, self.time_cost, self.parallelism);

        // fuse == accumulate: every validator runs, all errors are collected.
        // `fuse` appends via the `Append` trait, flattening into a single tuple:
        // (KeyPrefix, usize, Option<ChecksumSpec>, HashSpec).
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
        // A missing prefix is fatal for this field; no further rules apply.
        None => return Valid::fail(ConfigError::MissingPrefix).trace("prefix"),
    };

    // Each rule is a Valid<(), _, _> that either succeeds (noop) or fails.
    // `when` fails when the predicate is true; otherwise it succeeds with ().
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

    // Collect all rule violations, then materialize the newtype on success.
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

fn validate_checksum(
    enabled: bool,
    algo: ChecksumAlgo,
    length: usize,
) -> Vc<Option<ChecksumSpec>> {
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

fn validate_hash(memory_cost: u32, time_cost: u32, parallelism: u32) -> Vc<HashSpec> {
    // Probe the Argon2 library for parameter validity. In the real redesign this
    // check moves out of `HashConfig` (removing the "bad idea to do it here"
    // comment) and lives here in the config layer where it belongs.
    match argon2::Params::new(memory_cost, time_cost, parallelism, None) {
        Ok(_) => Valid::succeed(HashSpec {
            memory_cost,
            time_cost,
            parallelism,
        }),
        Err(_) => Valid::fail(ConfigError::InvalidHashParams).trace("hash"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_default_config_builds() {
        let cfg = ConfigBuilder::new().prefix("sk").build().unwrap();
        assert_eq!(cfg.prefix.as_str(), "sk");
        assert_eq!(cfg.entropy_bytes, 24);
        assert_eq!(cfg.checksum.unwrap().length, 32);
        assert_eq!(cfg.version, 0);
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
        assert!(cfg.checksum.is_none());
    }

    /// The headline feature: MANY problems across MANY fields, one error bundle.
    #[test]
    fn all_errors_accumulate_across_fields() {
        let err = ConfigBuilder::new()
            .prefix("bad prefix") // invalid chars (space)
            .entropy(4) // too low
            .checksum(ChecksumAlgo::Blake3, 8) // too small
            .hash_params(0, 0, 0) // invalid argon2 params
            .build()
            .unwrap_err();

        let errors = err.errors();
        assert!(
            errors.contains(&ConfigError::InvalidPrefixCharacters),
            "missing prefix-chars error in {errors:?}"
        );
        assert!(
            errors.contains(&ConfigError::EntropyTooLow),
            "missing entropy error in {errors:?}"
        );
        assert!(
            errors.contains(&ConfigError::ChecksumLenTooSmall),
            "missing checksum error in {errors:?}"
        );
        assert!(
            errors.contains(&ConfigError::InvalidHashParams),
            "missing hash error in {errors:?}"
        );
        assert!(errors.len() >= 4, "expected >= 4 errors, got {errors:?}");
    }

    /// Multiple rules WITHIN a single field also accumulate: this prefix is both
    /// too long AND contains the reserved substring "live".
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
        assert!(err.errors().contains(&ConfigError::InvalidPrefixVersionLike));
    }

    #[test]
    fn display_lists_every_error() {
        let err = ConfigBuilder::new()
            .prefix("live") // reserved substring
            .entropy(4) // too low
            .build()
            .unwrap_err();

        let text = err.to_string();
        assert!(text.contains("error(s)"));
        // Two distinct problems present in the rendered message.
        assert!(text.matches("  - ").count() >= 2, "rendered: {text}");
    }
}
