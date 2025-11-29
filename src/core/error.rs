//! Error types for PASERK operations.
//!
//! This module provides a unified error type for all PASERK operations.
//! Error messages are intentionally vague for security-sensitive operations
//! to avoid leaking information that could aid attacks.

use thiserror::Error;

/// Errors that can occur when working with PASERK keys.
#[derive(Debug, Error)]
pub enum PaserkError {
    /// The PASERK string format is invalid.
    #[error("Invalid PASERK format")]
    InvalidFormat,

    /// The PASERK header is invalid or doesn't match the expected version/type.
    #[error("Invalid PASERK header")]
    InvalidHeader,

    /// The PASERK version is not supported or doesn't match.
    #[error("Invalid or unsupported PASERK version")]
    InvalidVersion,

    /// The key material is invalid (wrong size, format, etc.).
    #[error("Invalid key material")]
    InvalidKey,

    /// Decryption failed (wrong password, corrupted data, etc.).
    /// Intentionally vague for security.
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Authentication tag verification failed.
    /// Intentionally vague for security.
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Key derivation failed (PBKDF2 or Argon2).
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Base64 decoding error.
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// The wrap protocol is not supported.
    #[error("Unsupported wrap protocol: {0}")]
    UnsupportedProtocol(String),

    /// Generic cryptographic error.
    /// Intentionally vague for security.
    #[error("Cryptographic operation failed")]
    CryptoError,
}

/// Result type alias for PASERK operations.
pub type PaserkResult<T> = Result<T, PaserkError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PaserkError::InvalidFormat;
        assert_eq!(err.to_string(), "Invalid PASERK format");

        let err = PaserkError::InvalidHeader;
        assert_eq!(err.to_string(), "Invalid PASERK header");

        let err = PaserkError::InvalidVersion;
        assert_eq!(err.to_string(), "Invalid or unsupported PASERK version");

        let err = PaserkError::InvalidKey;
        assert_eq!(err.to_string(), "Invalid key material");

        let err = PaserkError::DecryptionFailed;
        assert_eq!(err.to_string(), "Decryption failed");

        let err = PaserkError::AuthenticationFailed;
        assert_eq!(err.to_string(), "Authentication failed");

        let err = PaserkError::KeyDerivationFailed;
        assert_eq!(err.to_string(), "Key derivation failed");

        let err = PaserkError::UnsupportedProtocol("custom".to_string());
        assert_eq!(err.to_string(), "Unsupported wrap protocol: custom");

        let err = PaserkError::CryptoError;
        assert_eq!(err.to_string(), "Cryptographic operation failed");
    }

    #[test]
    fn test_error_debug() {
        let err = PaserkError::InvalidFormat;
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("InvalidFormat"));
    }
}
