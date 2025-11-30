//! `PaserkSecretId` - Secret key identifier.
//!
//! This module provides the `PaserkSecretId` type for key identifiers
//! computed from secret keys.
//!
//! Format: `k{version}.sid.{base64url(hash)}`

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::PaserkError;
use crate::core::header::validate_header;
use crate::core::operations::id::{compute_id, ID_HASH_SIZE};
use crate::core::types::PaserkSecret;
use crate::core::version::PaserkVersion;

/// A key identifier for a secret key (sid type).
///
/// Format: `k{version}.sid.{base64url(hash)}`
///
/// The hash is computed from the full PASERK string of the source key.
///
/// # Example
///
/// ```rust
/// use paserk::core::types::{PaserkSecret, PaserkSecretId};
/// use paserk::core::version::K4;
///
/// let key = PaserkSecret::<K4>::from([0u8; 64]);
/// let key_id: PaserkSecretId<K4> = (&key).into();
///
/// let id_string = key_id.to_string();
/// assert!(id_string.starts_with("k4.sid."));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PaserkSecretId<V: PaserkVersion> {
    /// The 33-byte hash (264 bits).
    id: [u8; ID_HASH_SIZE],
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkSecretId<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "sid";

    /// Creates a new `PaserkSecretId` from a pre-computed hash.
    #[must_use]
    pub(crate) const fn new(id: [u8; ID_HASH_SIZE]) -> Self {
        Self {
            id,
            _version: PhantomData,
        }
    }

    /// Returns the header for this PASERK type (e.g., "k4.sid.").
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
// From PaserkSecret (computes the ID)
// =============================================================================

impl<V: PaserkVersion> From<&PaserkSecret<V>> for PaserkSecretId<V> {
    fn from(key: &PaserkSecret<V>) -> Self {
        let paserk_string = key.to_string();
        let header = Self::header();
        let id = compute_id::<V>(&header, &paserk_string);
        Self::new(id)
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkSecretId<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(self.id);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug
// =============================================================================

impl<V: PaserkVersion> Debug for PaserkSecretId<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkSecretId")
            .field("version", &V::PREFIX)
            .field("id", &BASE64_URL_SAFE_NO_PAD.encode(self.id))
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkSecretId<V> {
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

impl<V: PaserkVersion> TryFrom<String> for PaserkSecretId<V> {
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

    const TEST_KEY_64: [u8; 64] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c,
        0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        0xac, 0xad, 0xae, 0xaf,
    ];

    #[test]
    #[cfg(feature = "k4")]
    fn test_compute_sid_k4() {
        let key = PaserkSecret::<K4>::from(TEST_KEY_64);
        let key_id: PaserkSecretId<K4> = (&key).into();
        let id_string = key_id.to_string();

        assert!(id_string.starts_with("k4.sid."));
        assert_eq!(id_string.len(), "k4.sid.".len() + 44); // 33 bytes = 44 base64 chars
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_sid_roundtrip() -> Result<(), PaserkError> {
        let key = PaserkSecret::<K4>::from(TEST_KEY_64);
        let key_id: PaserkSecretId<K4> = (&key).into();
        let serialized = key_id.to_string();

        let parsed = PaserkSecretId::<K4>::try_from(serialized.as_str())?;
        assert_eq!(key_id, parsed);
        Ok(())
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkSecretId::<K4>::header(), "k4.sid.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() {
        let key = PaserkSecret::<K4>::from(TEST_KEY_64);
        let key_id: PaserkSecretId<K4> = (&key).into();
        let debug_str = format!("{key_id:?}");
        assert!(debug_str.contains("PaserkSecretId"));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_different_keys_different_ids() {
        let key1 = PaserkSecret::<K4>::from([0u8; 64]);
        let key2 = PaserkSecret::<K4>::from([1u8; 64]);

        let id1: PaserkSecretId<K4> = (&key1).into();
        let id2: PaserkSecretId<K4> = (&key2).into();

        assert_ne!(id1, id2);
    }
}
