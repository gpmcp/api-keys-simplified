//! Shared checksum computation and constant-time verification.
//!
//! This module is the concrete fix for the old `verify -> generator` cross
//! dependency: checksum logic used to live inside `KeyGenerator`, so the verify
//! path had to reach into the generate path to validate a checksum. It now lives
//! here in the shared layer, with a pure `compute` (used by generate to *append*)
//! and a constant-time `verify_ct` (used by verify to *check*). Neither the
//! generate nor verify layer imports the other.

use subtle::ConstantTimeEq;

use crate::config::{ChecksumAlgo, ChecksumSpec};

/// Computes checksums for a specific validated [`ChecksumSpec`].
#[derive(Debug, Clone, Copy)]
pub struct Checksummer {
    spec: ChecksumSpec,
}

impl Checksummer {
    pub fn new(spec: ChecksumSpec) -> Self {
        Self { spec }
    }

    /// Pure: hash the key (and optional expiry bytes) and return the hex-encoded
    /// checksum truncated to the configured length.
    ///
    /// This function makes no policy decisions — it always produces a checksum.
    /// Whether a checksum is used at all is decided by the caller via the
    /// presence of a [`ChecksumSpec`] in the config.
    pub fn compute(&self, key: &[u8], expiry: Option<&[u8]>) -> String {
        match self.spec.algo {
            ChecksumAlgo::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(key);
                if let Some(expiry) = expiry {
                    hasher.update(expiry);
                }
                let hash = hasher.finalize();
                hash.to_hex()[..self.spec.length].to_string()
            }
        }
    }

    /// Constant-time comparison of an expected checksum against the freshly
    /// computed one. Used only by the verify path.
    pub fn verify_ct(&self, key: &[u8], expiry: Option<&[u8]>, expected: &[u8]) -> bool {
        let computed = self.compute(key, expiry);
        computed.as_bytes().ct_eq(expected).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ChecksumSpec {
        ChecksumSpec {
            algo: ChecksumAlgo::Blake3,
            length: 32,
        }
    }

    #[test]
    fn compute_is_deterministic() {
        let c = Checksummer::new(spec());
        assert_eq!(c.compute(b"key", None), c.compute(b"key", None));
    }

    #[test]
    fn compute_respects_length() {
        let c = Checksummer::new(spec());
        assert_eq!(c.compute(b"key", None).len(), 32);
    }

    #[test]
    fn expiry_changes_output() {
        let c = Checksummer::new(spec());
        assert_ne!(c.compute(b"key", None), c.compute(b"key", Some(b"exp")));
    }

    #[test]
    fn verify_ct_matches_compute() {
        let c = Checksummer::new(spec());
        let sum = c.compute(b"key", Some(b"exp"));
        assert!(c.verify_ct(b"key", Some(b"exp"), sum.as_bytes()));
        assert!(!c.verify_ct(b"key", None, sum.as_bytes()));
        assert!(!c.verify_ct(b"other", Some(b"exp"), sum.as_bytes()));
    }
}
