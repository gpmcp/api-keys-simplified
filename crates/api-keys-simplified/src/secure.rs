//! Secure memory handling for sensitive data
//!
//! This module provides types that automatically zero their memory on drop,
//! preventing sensitive data from lingering in memory after use.

use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure string that automatically zeros its memory on drop.
///
/// This type should be used for any sensitive data like API keys, tokens,
/// or passwords to prevent potential memory disclosure through:
/// - Core dumps
/// - Swap files
/// - Memory scanning tools
/// - Debuggers
///
/// # Security
///
/// The contained data is automatically zeroed when the value is dropped,
/// using the `zeroize` crate which provides compiler-fence-backed guarantees
/// that the zeroing operation won't be optimized away.
///
/// # Design: Why No `Deref<Target=str>`?
///
/// This type **intentionally does NOT implement `Deref`** to maintain security:
///
/// - **Explicit access**: Requires `.as_ref()` call, making code auditable
/// - **Prevents silent leakage**: No implicit coercion to `&str` in logs/errors  
/// - **Grep-able security**: Easy to audit with `git grep "\.as_ref\(\)"`
/// - **Industry standard**: Aligns with `secrecy` crate's proven approach
///
/// The slight ergonomic cost of typing `.as_ref()` is a worthwhile
/// security trade-off that prevents accidental secret exposure.
///
/// # Example
///
/// ```
/// use api_keys_simplified::SecureString;
/// // Note that unlike this example, never use string literal
/// // to convert to SecureString. Dropping SecureString will NOT
/// // zeroize the string literal in memory.
/// let sensitive = SecureString::from("my_secret_api_key".to_string());
///
/// // Explicit access (good - auditable)
/// let key = sensitive.as_ref();
///
/// // Debug output is automatically redacted (safe)
/// println!("{:?}", sensitive);  // Output: "SecureString([REDACTED])"
/// ```
///
/// // Memory is automatically zeroed when `sensitive` goes out of scope
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl SecureString {
    /// Creates a new SecureString from a String.
    ///
    /// The original string is moved and will be zeroed when this
    /// SecureString is dropped.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Returns the length of the string in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// Prevent accidental logging of sensitive data
impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureString([REDACTED])")
    }
}

// Prevent accidental display of sensitive data
impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_creation() {
        let secret = SecureString::from("my_secret".to_string());
        assert_eq!(secret.as_ref(), "my_secret");
        assert_eq!(secret.len(), 9);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secure_string_redaction() {
        let secret = SecureString::from("sensitive_data".to_string());

        // Debug output should be redacted
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "SecureString([REDACTED])");
        assert!(!debug_output.contains("sensitive_data"));

        // Display output should be redacted
        let display_output = format!("{}", secret);
        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("sensitive_data"));
    }

    #[test]
    fn test_secure_string_empty() {
        let empty = SecureString::from("".to_string());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_as_ref() {
        let secret = SecureString::from("test".to_string());
        let reference: &str = secret.as_ref();
        assert_eq!(reference, "test");
    }
}
