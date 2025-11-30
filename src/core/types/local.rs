//! `PaserkLocal` - Symmetric key serialization.
//!
//! This module provides the `PaserkLocal` type for serializing symmetric
//! (local) keys in PASERK format.
//!
//! Format: `k{version}.local.{base64url(key)}`

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;
use zeroize::Zeroize;

use crate::core::error::PaserkError;
use crate::core::header::validate_header;
use crate::core::version::PaserkVersion;

/// A symmetric key serialized in PASERK format.
///
/// Format: `k{version}.local.{base64url(key)}`
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
/// use paserk::core::types::PaserkLocal;
/// use paserk::core::version::K4;
///
/// // Create from raw bytes
/// let key_bytes: [u8; 32] = [0u8; 32];
/// let paserk_key = PaserkLocal::<K4>::from(key_bytes);
///
/// // Serialize to string
/// let paserk_string = paserk_key.to_string();
/// assert!(paserk_string.starts_with("k4.local."));
///
/// // Parse from string
/// let parsed = PaserkLocal::<K4>::try_from(paserk_string.as_str());
/// assert!(parsed.is_ok());
/// ```
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PaserkLocal<V: PaserkVersion> {
    key: [u8; 32],
    #[zeroize(skip)]
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkLocal<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "local";

    /// Creates a new `PaserkLocal` from raw key bytes.
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            _version: PhantomData,
        }
    }

    /// Returns the header for this PASERK type (e.g., "k4.local.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Returns a reference to the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Consumes the `PaserkLocal` and returns the raw key bytes.
    #[must_use]
    pub fn into_bytes(self) -> [u8; 32] {
        self.key
    }
}

// =============================================================================
// From implementations (infallible)
// =============================================================================

impl<V: PaserkVersion> From<[u8; 32]> for PaserkLocal<V> {
    fn from(key: [u8; 32]) -> Self {
        Self::new(key)
    }
}

impl<V: PaserkVersion> From<&[u8; 32]> for PaserkLocal<V> {
    fn from(key: &[u8; 32]) -> Self {
        Self::new(*key)
    }
}

// =============================================================================
// AsRef implementations
// =============================================================================

impl<V: PaserkVersion> AsRef<[u8]> for PaserkLocal<V> {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl<V: PaserkVersion> AsRef<[u8; 32]> for PaserkLocal<V> {
    fn as_ref(&self) -> &[u8; 32] {
        &self.key
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkLocal<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(self.key);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug (security: don't expose key material)
// =============================================================================

impl<V: PaserkVersion> Debug for PaserkLocal<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkLocal")
            .field("version", &V::PREFIX)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkLocal<V> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let encoded_key = validate_header(paserk, V::PREFIX, Self::TYPE)?;

        let key_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_key)
            .map_err(PaserkError::Base64Decode)?;

        if key_bytes.len() != 32 {
            return Err(PaserkError::InvalidKey);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        Ok(Self::new(key))
    }
}

impl<V: PaserkVersion> TryFrom<String> for PaserkLocal<V> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq (constant-time comparison)
// =============================================================================

impl<V: PaserkVersion> PartialEq for PaserkLocal<V> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.key.ct_eq(&other.key).into()
    }
}

impl<V: PaserkVersion> Eq for PaserkLocal<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    // Test vector from PASERK spec
    const TEST_KEY: [u8; 32] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f,
    ];
    const TEST_PASERK_K4: &str = "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8";

    #[test]
    fn test_from_bytes() {
        let paserk = PaserkLocal::<K4>::from(TEST_KEY);
        assert_eq!(paserk.as_bytes(), &TEST_KEY);
    }

    #[test]
    fn test_from_ref_bytes() {
        let paserk = PaserkLocal::<K4>::from(&TEST_KEY);
        assert_eq!(paserk.as_bytes(), &TEST_KEY);
    }

    #[test]
    fn test_to_string() {
        let paserk = PaserkLocal::<K4>::from(TEST_KEY);
        assert_eq!(paserk.to_string(), TEST_PASERK_K4);
    }

    #[test]
    fn test_try_from_str() -> Result<(), PaserkError> {
        let paserk = PaserkLocal::<K4>::try_from(TEST_PASERK_K4)?;
        assert_eq!(paserk.as_bytes(), &TEST_KEY);
        Ok(())
    }

    #[test]
    fn test_roundtrip() -> Result<(), PaserkError> {
        let original = PaserkLocal::<K4>::from(TEST_KEY);
        let serialized = original.to_string();
        let parsed = PaserkLocal::<K4>::try_from(serialized.as_str())?;
        assert_eq!(original, parsed);
        Ok(())
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkLocal::<K4>::header(), "k4.local.");
    }

    #[test]
    fn test_into_bytes() {
        let paserk = PaserkLocal::<K4>::from(TEST_KEY);
        let bytes = paserk.into_bytes();
        assert_eq!(bytes, TEST_KEY);
    }

    #[test]
    fn test_as_ref_slice() {
        let paserk = PaserkLocal::<K4>::from(TEST_KEY);
        let slice: &[u8] = paserk.as_ref();
        assert_eq!(slice, &TEST_KEY);
    }

    #[test]
    fn test_as_ref_array() {
        let paserk = PaserkLocal::<K4>::from(TEST_KEY);
        let array: &[u8; 32] = paserk.as_ref();
        assert_eq!(array, &TEST_KEY);
    }

    #[test]
    fn test_debug_redacts_key() {
        let paserk = PaserkLocal::<K4>::from(TEST_KEY);
        let debug_str = format!("{paserk:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("70")); // Should not contain key bytes
    }

    #[test]
    fn test_equality() {
        let a = PaserkLocal::<K4>::from(TEST_KEY);
        let b = PaserkLocal::<K4>::from(TEST_KEY);
        assert_eq!(a, b);

        let c = PaserkLocal::<K4>::from([0u8; 32]);
        assert_ne!(a, c);
    }

    #[test]
    fn test_clone() {
        let original = PaserkLocal::<K4>::from(TEST_KEY);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_invalid_header() {
        let result = PaserkLocal::<K4>::try_from("k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));

        let result = PaserkLocal::<K4>::try_from("k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_invalid_key_length() {
        // Too short (only 16 bytes)
        let result = PaserkLocal::<K4>::try_from("k4.local.AAAAAAAAAAAAAAAAAAAAAA");
        assert!(matches!(result, Err(PaserkError::InvalidKey)));
    }

    #[test]
    fn test_invalid_base64() {
        let result = PaserkLocal::<K4>::try_from("k4.local.!!!invalid!!!");
        assert!(matches!(result, Err(PaserkError::Base64Decode(_))));
    }
}
