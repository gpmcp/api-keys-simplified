//! Secure memory handling for sensitive data

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// A secure string that automatically zeros its memory on drop.
///
/// This is a type alias for `secrecy::SecretString`, which provides:
/// - Automatic memory zeroing on drop
/// - Prevention of accidental logging via Debug/Display
/// - Industry-standard security practices
///
/// # Security
///
/// The contained data is automatically zeroed when the value is dropped,
/// using the `zeroize` crate which provides compiler-fence-backed guarantees
/// that the zeroing operation won't be optimized away.
///
/// # Usage
///
/// Access the underlying string using `.expose_secret()`:
///
/// ```rust
/// use api_keys_simplified::SecureString;
/// use api_keys_simplified::ExposeSecret;
///
/// let secret = SecureString::from("my_secret".to_string());
/// let value: &str = secret.expose_secret();
/// ```
///
/// # Design: Why No `Deref<Target=str>`?
///
/// This type **intentionally does NOT implement `Deref`** to maintain security:
///
/// - **Explicit access**: Requires `.expose_secret()` call, making code auditable
/// - **Prevents silent leakage**: No implicit coercion to `&str` in logs/errors
/// - **Grep-able security**: Easy to audit with `git grep "\.expose_secret\(\)"`
/// - **Industry standard**: Uses the battle-tested `secrecy` crate
pub type SecureString = SecretString;

/// Extension trait to add convenience methods to SecureString
pub trait SecureStringExt {
    /// Returns the length of the string in bytes.
    fn len(&self) -> usize;

    /// Returns true if the string is empty.
    fn is_empty(&self) -> bool;

    /// Constant time eq
    // FIXME: we can add wrapper to secure
    // string and impl PartialEq
    fn eq(&self, other: &Self) -> bool;
}

impl SecureStringExt for SecureString {
    fn len(&self) -> usize {
        self.expose_secret().len()
    }

    fn is_empty(&self) -> bool {
        self.expose_secret().is_empty()
    }

    fn eq(&self, other: &Self) -> bool {
        self.expose_secret()
            .as_bytes()
            .ct_eq(other.expose_secret().as_bytes())
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_creation() {
        let secret = SecretString::from("my_secret");
        assert_eq!(secret.expose_secret(), "my_secret");
        assert_eq!(secret.len(), 9);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secure_string_redaction() {
        let secret = SecretString::from("sensitive_data");

        // Debug output should be redacted by secrecy crate
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("sensitive_data"));
        assert!(debug_output.contains("Secret"));
    }

    #[test]
    fn test_secure_string_empty() {
        let empty = SecretString::from("");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_expose_secret() {
        let secret = SecretString::from("test".to_string());
        let reference: &str = secret.expose_secret();
        assert_eq!(reference, "test");
    }
}
