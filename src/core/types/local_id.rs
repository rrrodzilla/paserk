//! `PaserkLocalId` - Symmetric key identifier.
//!
//! This module provides the `PaserkLocalId` type for key identifiers
//! computed from symmetric (local) keys.
//!
//! Format: `k{version}.lid.{base64url(hash)}`
//!
//! The hash is computed from the full PASERK string of the source key.

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::PaserkError;
use crate::core::header::validate_header;
use crate::core::operations::id::{compute_id, ID_HASH_SIZE};
use crate::core::types::PaserkLocal;
use crate::core::version::PaserkVersion;

/// A key identifier for a symmetric key (lid type).
///
/// Format: `k{version}.lid.{base64url(hash)}`
///
/// The hash is computed from the full PASERK string of the source key using:
/// - SHA-384 truncated to 33 bytes for K1/K3
/// - BLAKE2b-264 (33 bytes) for K2/K4
///
/// # Example
///
/// ```rust
/// use paserk::core::types::{PaserkLocal, PaserkLocalId};
/// use paserk::core::version::K4;
///
/// let key = PaserkLocal::<K4>::from([0u8; 32]);
/// let key_id: PaserkLocalId<K4> = (&key).into();
///
/// let id_string = key_id.to_string();
/// assert!(id_string.starts_with("k4.lid."));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PaserkLocalId<V: PaserkVersion> {
    /// The 33-byte hash (264 bits).
    id: [u8; ID_HASH_SIZE],
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkLocalId<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "lid";

    /// Creates a new `PaserkLocalId` from a pre-computed hash.
    #[must_use]
    pub(crate) const fn new(id: [u8; ID_HASH_SIZE]) -> Self {
        Self {
            id,
            _version: PhantomData,
        }
    }

    /// Returns the header for this PASERK type (e.g., "k4.lid.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Returns a reference to the raw ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_HASH_SIZE] {
        &self.id
    }
}

// =============================================================================
// From PaserkLocal (computes the ID)
// =============================================================================

impl<V: PaserkVersion> From<&PaserkLocal<V>> for PaserkLocalId<V> {
    fn from(key: &PaserkLocal<V>) -> Self {
        let paserk_string = key.to_string();
        let header = Self::header();
        let id = compute_id::<V>(&header, &paserk_string);
        Self::new(id)
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkLocalId<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(self.id);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug
// =============================================================================

impl<V: PaserkVersion> Debug for PaserkLocalId<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkLocalId")
            .field("version", &V::PREFIX)
            .field("id", &BASE64_URL_SAFE_NO_PAD.encode(self.id))
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkLocalId<V> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let encoded_id = validate_header(paserk, V::PREFIX, Self::TYPE)?;

        let id_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_id)
            .map_err(PaserkError::Base64Decode)?;

        if id_bytes.len() != ID_HASH_SIZE {
            return Err(PaserkError::InvalidKey);
        }

        let mut id = [0u8; ID_HASH_SIZE];
        id.copy_from_slice(&id_bytes);

        Ok(Self::new(id))
    }
}

impl<V: PaserkVersion> TryFrom<String> for PaserkLocalId<V> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

#[cfg(test)]
#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
mod tests {
    use super::*;
    use crate::core::version::K4;

    // Test vector from PASERK spec
    const TEST_KEY: [u8; 32] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f,
    ];

    // Expected lid from PASERK spec for K4
    const EXPECTED_LID_K4: &str = "k4.lid.iVtYQDjr5gEijCSjJC3fQaJm7nCeQSeaty0Jixy8dbsk";

    #[test]
    #[cfg(feature = "k4")]
    fn test_compute_lid_k4() {
        let key = PaserkLocal::<K4>::from(TEST_KEY);
        let key_id: PaserkLocalId<K4> = (&key).into();
        let id_string = key_id.to_string();

        assert_eq!(id_string, EXPECTED_LID_K4);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_parse_lid_k4() -> Result<(), PaserkError> {
        let key_id = PaserkLocalId::<K4>::try_from(EXPECTED_LID_K4)?;
        assert_eq!(key_id.to_string(), EXPECTED_LID_K4);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_lid_roundtrip() -> Result<(), PaserkError> {
        let key = PaserkLocal::<K4>::from(TEST_KEY);
        let key_id: PaserkLocalId<K4> = (&key).into();
        let serialized = key_id.to_string();

        let parsed = PaserkLocalId::<K4>::try_from(serialized.as_str())?;
        assert_eq!(key_id, parsed);
        Ok(())
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkLocalId::<K4>::header(), "k4.lid.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() {
        let key = PaserkLocal::<K4>::from(TEST_KEY);
        let key_id: PaserkLocalId<K4> = (&key).into();
        let debug_str = format!("{key_id:?}");
        assert!(debug_str.contains("PaserkLocalId"));
        assert!(debug_str.contains("k4"));
    }

    #[test]
    fn test_invalid_version() {
        let result =
            PaserkLocalId::<K4>::try_from("k2.lid.iVtYQDjr5gEijCSjJC3fQaJm7nCeQSeaty0Jixy8dbsk");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_invalid_type() {
        let result =
            PaserkLocalId::<K4>::try_from("k4.pid.iVtYQDjr5gEijCSjJC3fQaJm7nCeQSeaty0Jixy8dbsk");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }
}
