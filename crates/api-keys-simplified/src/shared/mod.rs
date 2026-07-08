//! # Shared layer (level 1)
//!
//! Building blocks used by **both** the generate and verify layers. Nothing in
//! here depends on `generate`, `verify`, or `manager` — the dependency arrows
//! only ever point downward into `config`. This is what lets generation and
//! verification share logic (checksum, hashing, token parsing, secure strings)
//! without importing each other.

pub mod checksum;
pub mod hasher;
pub mod secure;
pub mod token_parser;

/// Maximum accepted API key length (DoS protection against oversized inputs).
pub(crate) const MAX_KEY_LENGTH: usize = 512;

/// Maximum accepted stored-hash length (DoS protection against malformed hashes).
pub(crate) const MAX_HASH_LENGTH: usize = 512;

/// Byte that separates the key body from the checksum / expiry segments.
pub(crate) const CHECKSUM_SEPARATOR: u8 = b'.';
