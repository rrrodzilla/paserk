//! PaserkSecret - Secret key serialization.
//!
//! This module provides the `PaserkSecret` type for serializing secret
//! (signing) keys in PASERK format.
//!
//! Format: `k{version}.secret.{base64url(key)}`
//!
//! Secret key sizes vary by version:
//! - K1: RSA private key (variable)
//! - K2/K4: Ed25519 secret key (64 bytes)
//! - K3: P-384 secret key (48 bytes)

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;
use zeroize::Zeroize;

use crate::core::error::PaserkError;
use crate::core::header::validate_header;
use crate::core::version::PaserkVersion;

/// A secret key serialized in PASERK format.
///
/// Format: `k{version}.secret.{base64url(key)}`
///
/// This type handles Ed25519 secret keys (64 bytes) for K2 and K4 versions.
/// K1 (RSA) and K3 (P-384) use different key sizes.
///
/// # Security
///
/// - Key material is zeroized on drop
/// - Debug output redacts the key
/// - Equality comparison uses constant-time comparison
///
/// # Example
///
/// ```rust
/// use paserk::core::types::PaserkSecret;
/// use paserk::core::version::K4;
///
/// // Create from raw bytes (Ed25519 secret key)
/// let key_bytes: [u8; 64] = [0u8; 64];
/// let paserk_key = PaserkSecret::<K4>::from(key_bytes);
///
/// // Serialize to string
/// let paserk_string = paserk_key.to_string();
/// assert!(paserk_string.starts_with("k4.secret."));
/// ```
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PaserkSecret<V: PaserkVersion> {
    /// The raw secret key bytes.
    /// For K2/K4: 64 bytes (Ed25519)
    /// For K3: 48 bytes (P-384)
    /// For K1: variable (RSA)
    key: Vec<u8>,
    #[zeroize(skip)]
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkSecret<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "secret";

    /// Returns the header for this PASERK type (e.g., "k4.secret.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Returns a reference to the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Consumes the `PaserkSecret` and returns the raw key bytes.
    ///
    /// Note: This clones the key material before the original is zeroized.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.key.clone()
    }

    /// Creates a new `PaserkSecret` from arbitrary bytes.
    ///
    /// # Safety
    ///
    /// This does not validate the key format. Use the `TryFrom` implementations
    /// for validated parsing.
    fn from_bytes_unchecked(key: Vec<u8>) -> Self {
        Self {
            key,
            _version: PhantomData,
        }
    }
}

// =============================================================================
// From implementations for Ed25519 keys (K2, K4) - 64 bytes
// =============================================================================

impl<V: PaserkVersion> From<[u8; 64]> for PaserkSecret<V> {
    fn from(key: [u8; 64]) -> Self {
        Self::from_bytes_unchecked(key.to_vec())
    }
}

impl<V: PaserkVersion> From<&[u8; 64]> for PaserkSecret<V> {
    fn from(key: &[u8; 64]) -> Self {
        Self::from_bytes_unchecked(key.to_vec())
    }
}

// =============================================================================
// From implementations for P-384 keys (K3) - 48 bytes
// =============================================================================

impl<V: PaserkVersion> From<[u8; 48]> for PaserkSecret<V> {
    fn from(key: [u8; 48]) -> Self {
        Self::from_bytes_unchecked(key.to_vec())
    }
}

impl<V: PaserkVersion> From<&[u8; 48]> for PaserkSecret<V> {
    fn from(key: &[u8; 48]) -> Self {
        Self::from_bytes_unchecked(key.to_vec())
    }
}

// =============================================================================
// AsRef implementations
// =============================================================================

impl<V: PaserkVersion> AsRef<[u8]> for PaserkSecret<V> {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkSecret<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&self.key);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug (security: don't expose key material)
// =============================================================================

impl<V: PaserkVersion> Debug for PaserkSecret<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkSecret")
            .field("version", &V::PREFIX)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkSecret<V> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let encoded_key = validate_header(paserk, V::PREFIX, Self::TYPE)?;

        let key_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_key)
            .map_err(PaserkError::Base64Decode)?;

        // Validate key length based on version
        let valid_len = match V::VERSION {
            2 | 4 => key_bytes.len() == 64, // Ed25519
            3 => key_bytes.len() == 48,     // P-384
            1 => key_bytes.len() >= 256,    // RSA (minimum reasonable size)
            _ => false,
        };

        if !valid_len {
            return Err(PaserkError::InvalidKey);
        }

        Ok(Self::from_bytes_unchecked(key_bytes))
    }
}

impl<V: PaserkVersion> TryFrom<String> for PaserkSecret<V> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq (constant-time comparison)
// =============================================================================

impl<V: PaserkVersion> PartialEq for PaserkSecret<V> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        // Handle different lengths
        if self.key.len() != other.key.len() {
            return false;
        }
        self.key.ct_eq(&other.key).into()
    }
}

impl<V: PaserkVersion> Eq for PaserkSecret<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    const TEST_KEY_64: [u8; 64] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
        0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        0xac, 0xad, 0xae, 0xaf,
    ];

    #[test]
    fn test_from_bytes() {
        let paserk = PaserkSecret::<K4>::from(TEST_KEY_64);
        assert_eq!(paserk.as_bytes(), &TEST_KEY_64);
    }

    #[test]
    fn test_roundtrip_k4() -> Result<(), PaserkError> {
        let original = PaserkSecret::<K4>::from(TEST_KEY_64);
        let serialized = original.to_string();
        assert!(serialized.starts_with("k4.secret."));

        let parsed = PaserkSecret::<K4>::try_from(serialized.as_str())?;
        assert_eq!(original, parsed);
        Ok(())
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkSecret::<K4>::header(), "k4.secret.");
    }

    #[test]
    fn test_debug_redacts_key() {
        let paserk = PaserkSecret::<K4>::from(TEST_KEY_64);
        let debug_str = format!("{paserk:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("70")); // Should not contain key bytes
    }

    #[test]
    fn test_equality() {
        let a = PaserkSecret::<K4>::from(TEST_KEY_64);
        let b = PaserkSecret::<K4>::from(TEST_KEY_64);
        assert_eq!(a, b);

        let c = PaserkSecret::<K4>::from([0u8; 64]);
        assert_ne!(a, c);
    }

    #[test]
    fn test_clone() {
        let original = PaserkSecret::<K4>::from(TEST_KEY_64);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_invalid_version() {
        // Create a valid K4 secret key string then try to parse as K4 with wrong version prefix
        let original = PaserkSecret::<K4>::from(TEST_KEY_64);
        let serialized = original.to_string();
        let wrong_version = serialized.replace("k4.", "k2.");

        let result = PaserkSecret::<K4>::try_from(wrong_version.as_str());
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_invalid_type() {
        let original = PaserkSecret::<K4>::from(TEST_KEY_64);
        let serialized = original.to_string();
        let wrong_type = serialized.replace(".secret.", ".local.");

        let result = PaserkSecret::<K4>::try_from(wrong_type.as_str());
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }
}
