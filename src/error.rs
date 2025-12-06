use thiserror::Error;

/// Error type for API key operations.
/// 
/// # Security Note
/// Error messages are intentionally generic to prevent information leakage.
/// For debugging, use `{:?}` formatting which includes additional context.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid input format or parameters
    #[error("Invalid input")]
    InvalidFormat,

    /// Configuration error with specific details
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Operation failed (intentionally vague for security)
    /// 
    /// This could be:
    /// - Key generation failure
    /// - Hashing failure
    /// - Verification failure
    /// 
    /// Use `{:?}` formatting to see details in logs.
    #[error("Operation failed")]
    OperationFailed(
        #[source]
        #[from]
        OperationError
    ),
}

/// Configuration errors with specific variants
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Prefix must be between 1 and 10 characters")]
    InvalidPrefixLength,

    #[error("Prefix must contain only alphanumeric characters or underscores")]
    InvalidPrefixCharacters,

    #[error("Prefix must not contain {0} substring")]
    InvalidPrefixSubstring(String),

    #[error("String must not be empty")]
    EmptyString,

    #[error("Entropy must be at least 16 bytes (128 bits)")]
    EntropyTooLow,

    #[error("Entropy cannot exceed 64 bytes (512 bits)")]
    EntropyTooHigh,

    #[error("Invalid Argon2 parameters")]
    InvalidHashParams,
}

/// Detailed operation errors for debugging (use {:?} to see these)
#[derive(Debug, Error)]
pub enum OperationError {
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),

    #[error("Hashing failed: {0}")]
    HashingFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_is_generic() {
        let err = Error::OperationFailed(
            OperationError::HashingFailed("detailed salt error".to_string())
        );
        
        // Display is generic (safe for clients)
        assert_eq!(err.to_string(), "Operation failed");
        
        // Debug contains details (for logging)
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("HashingFailed"));
        assert!(debug_str.contains("salt"));
    }

    #[test]
    fn test_error_chaining() {
        let err = Error::OperationFailed(
            OperationError::VerificationFailed("argon2 param error".to_string())
        );
        
        // Can access source for logging
        if let Error::OperationFailed(source) = err {
            assert!(source.to_string().contains("argon2"));
        }
    }

    #[test]
    fn test_format_errors_are_generic() {
        let err = Error::InvalidFormat;
        assert_eq!(err.to_string(), "Invalid input");
    }

    #[test]
    fn test_config_errors_are_specific() {
        let err = Error::Config(ConfigError::EntropyTooLow);
        assert_eq!(err.to_string(), "Entropy must be at least 16 bytes (128 bits)");

        let err = Error::Config(ConfigError::InvalidPrefixLength);
        assert_eq!(err.to_string(), "Prefix must be between 1 and 10 characters");
    }

    #[test]
    fn test_config_error_conversion() {
        // Test automatic conversion from ConfigError to Error
        let config_err = ConfigError::EmptyString;
        let err: Error = config_err.into();
        assert_eq!(err.to_string(), "String must not be empty");
    }
}
