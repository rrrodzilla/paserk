//! `PaserkPublic` - Public key serialization.
//!
//! This module provides the `PaserkPublic` type for serializing public
//! (verification) keys in PASERK format.
//!
//! Format: `k{version}.public.{base64url(key)}`
//!
//! Public key sizes vary by version:
//! - K1: RSA public key (variable, typically 512+ bytes)
//! - K2/K4: Ed25519 public key (32 bytes)
//! - K3: P-384 compressed public key (49 bytes)

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::PaserkError;
use crate::core::header::validate_header;
use crate::core::version::PaserkVersion;

/// A public key serialized in PASERK format.
///
/// Format: `k{version}.public.{base64url(key)}`
///
/// This type handles Ed25519 public keys (32 bytes) for K2 and K4 versions.
/// K1 (RSA) and K3 (P-384) use different key sizes and are handled separately.
///
/// # Example
///
/// ```rust
/// use paserk::core::types::PaserkPublic;
/// use paserk::core::version::K4;
///
/// // Create from raw bytes (Ed25519 public key)
/// let key_bytes: [u8; 32] = [0u8; 32];
/// let paserk_key = PaserkPublic::<K4>::from(key_bytes);
///
/// // Serialize to string
/// let paserk_string = paserk_key.to_string();
/// assert!(paserk_string.starts_with("k4.public."));
/// ```
#[derive(Clone)]
pub struct PaserkPublic<V: PaserkVersion> {
    /// The raw public key bytes.
    /// For K2/K4: 32 bytes (Ed25519)
    /// For K3: 49 bytes (P-384 compressed)
    /// For K1: variable (RSA)
    key: Vec<u8>,
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkPublic<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "public";

    /// Returns the header for this PASERK type (e.g., "k4.public.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Returns a reference to the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Consumes the `PaserkPublic` and returns the raw key bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.key
    }

    /// Creates a new `PaserkPublic` from arbitrary bytes.
    ///
    /// # Safety
    ///
    /// This does not validate the key format. Use the `TryFrom` implementations
    /// for validated parsing.
    const fn from_bytes_unchecked(key: Vec<u8>) -> Self {
        Self {
            key,
            _version: PhantomData,
        }
    }
}

// =============================================================================
// From implementations for Ed25519 keys (K2, K4)
// =============================================================================

impl<V: PaserkVersion> From<[u8; 32]> for PaserkPublic<V> {
    fn from(key: [u8; 32]) -> Self {
        Self::from_bytes_unchecked(key.to_vec())
    }
}

impl<V: PaserkVersion> From<&[u8; 32]> for PaserkPublic<V> {
    fn from(key: &[u8; 32]) -> Self {
        Self::from_bytes_unchecked(key.to_vec())
    }
}

// =============================================================================
// AsRef implementations
// =============================================================================

impl<V: PaserkVersion> AsRef<[u8]> for PaserkPublic<V> {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkPublic<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&self.key);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug
// =============================================================================

impl<V: PaserkVersion> Debug for PaserkPublic<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkPublic")
            .field("version", &V::PREFIX)
            .field("key_len", &self.key.len())
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkPublic<V> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let encoded_key = validate_header(paserk, V::PREFIX, Self::TYPE)?;

        let key_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_key)
            .map_err(PaserkError::Base64Decode)?;

        // Validate key length based on version
        let valid_len = match V::VERSION {
            2 | 4 => key_bytes.len() == 32, // Ed25519
            3 => key_bytes.len() == 49,     // P-384 compressed
            1 => key_bytes.len() >= 256,    // RSA (minimum reasonable size)
            _ => false,
        };

        if !valid_len {
            return Err(PaserkError::InvalidKey);
        }

        Ok(Self::from_bytes_unchecked(key_bytes))
    }
}

impl<V: PaserkVersion> TryFrom<String> for PaserkPublic<V> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq
// =============================================================================

impl<V: PaserkVersion> PartialEq for PaserkPublic<V> {
    fn eq(&self, other: &Self) -> bool {
        // Public keys don't need constant-time comparison
        self.key == other.key
    }
}

impl<V: PaserkVersion> Eq for PaserkPublic<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    const TEST_KEY_32: [u8; 32] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f,
    ];

    #[test]
    fn test_from_bytes() {
        let paserk = PaserkPublic::<K4>::from(TEST_KEY_32);
        assert_eq!(paserk.as_bytes(), &TEST_KEY_32);
    }

    #[test]
    fn test_roundtrip_k4() -> Result<(), PaserkError> {
        let original = PaserkPublic::<K4>::from(TEST_KEY_32);
        let serialized = original.to_string();
        assert!(serialized.starts_with("k4.public."));

        let parsed = PaserkPublic::<K4>::try_from(serialized.as_str())?;
        assert_eq!(original, parsed);
        Ok(())
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkPublic::<K4>::header(), "k4.public.");
    }

    #[test]
    fn test_debug() {
        let paserk = PaserkPublic::<K4>::from(TEST_KEY_32);
        let debug_str = format!("{paserk:?}");
        assert!(debug_str.contains("PaserkPublic"));
        assert!(debug_str.contains("key_len"));
    }

    #[test]
    fn test_invalid_version() {
        let result =
            PaserkPublic::<K4>::try_from("k2.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_invalid_type() {
        let result =
            PaserkPublic::<K4>::try_from("k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }
}
