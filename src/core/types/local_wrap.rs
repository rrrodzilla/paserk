//! PaserkLocalWrap - Symmetric key wrapped with another symmetric key.
//!
//! This module provides the `PaserkLocalWrap` type for storing symmetric keys
//! that have been encrypted with another symmetric key using a wrap protocol.
//!
//! Format: `k{version}.local-wrap.{protocol}.{base64url(nonce || ciphertext || tag)}`

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::{PaserkError, PaserkResult};
use crate::core::operations::wrap::{Pie, WrapProtocol, PIE_NONCE_SIZE, PIE_TAG_SIZE};
use crate::core::types::PaserkLocal;
use crate::core::version::PaserkVersion;

/// A symmetric key wrapped with another symmetric key.
///
/// Format: `k{version}.local-wrap.{protocol}.{base64url(nonce || ciphertext || tag)}`
///
/// This type represents a symmetric key that has been encrypted with another
/// symmetric key using the specified wrap protocol (typically PIE).
///
/// # Security
///
/// - The wrapped key material is encrypted
/// - Authentication tag prevents tampering
/// - Safe to include in PASETO token footers
///
/// # Example
///
/// ```rust
/// use paserk::core::types::{PaserkLocal, PaserkLocalWrap};
/// use paserk::core::operations::wrap::Pie;
/// use paserk::core::version::K4;
///
/// let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
/// let key_to_wrap = PaserkLocal::<K4>::from([0x13u8; 32]);
///
/// // Wrap the key
/// let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&key_to_wrap, &wrapping_key)
///     .expect("wrap should succeed");
///
/// // Serialize to PASERK string
/// let paserk_string = wrapped.to_string();
///
/// // Parse back
/// let parsed = PaserkLocalWrap::<K4, Pie>::try_from(paserk_string.as_str())
///     .expect("parse should succeed");
///
/// // Unwrap to get the original key
/// let unwrapped = parsed.try_unwrap(&wrapping_key)
///     .expect("unwrap should succeed");
/// ```
#[derive(Clone)]
pub struct PaserkLocalWrap<V: PaserkVersion, P: WrapProtocol> {
    /// The random nonce (32 bytes for PIE).
    nonce: [u8; PIE_NONCE_SIZE],
    /// The encrypted key (32 bytes for local keys).
    ciphertext: [u8; 32],
    /// The authentication tag (32 bytes for PIE).
    tag: [u8; PIE_TAG_SIZE],
    /// Version marker.
    _version: PhantomData<V>,
    /// Protocol marker.
    _protocol: PhantomData<P>,
}

impl<V: PaserkVersion, P: WrapProtocol> PaserkLocalWrap<V, P> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "local-wrap";

    /// Returns the header for this PASERK type (e.g., "k4.local-wrap.pie.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.{}.", V::PREFIX, Self::TYPE, P::PROTOCOL_ID)
    }

    /// Creates a new `PaserkLocalWrap` from raw components.
    fn new(nonce: [u8; PIE_NONCE_SIZE], ciphertext: [u8; 32], tag: [u8; PIE_TAG_SIZE]) -> Self {
        Self {
            nonce,
            ciphertext,
            tag,
            _version: PhantomData,
            _protocol: PhantomData,
        }
    }

    /// Returns a reference to the nonce bytes.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; PIE_NONCE_SIZE] {
        &self.nonce
    }

    /// Returns a reference to the ciphertext bytes.
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; 32] {
        &self.ciphertext
    }

    /// Returns a reference to the tag bytes.
    #[must_use]
    pub const fn tag(&self) -> &[u8; PIE_TAG_SIZE] {
        &self.tag
    }
}

// =============================================================================
// PIE wrapping for K2/K4
// =============================================================================

#[cfg(any(feature = "k2", feature = "k4"))]
impl<V: PaserkVersion + crate::core::version::UsesXChaCha20> PaserkLocalWrap<V, Pie> {
    /// Wraps a symmetric key using the PIE protocol.
    ///
    /// # Arguments
    ///
    /// * `key_to_wrap` - The symmetric key to wrap
    /// * `wrapping_key` - The symmetric key to use for wrapping
    ///
    /// # Returns
    ///
    /// A new `PaserkLocalWrap` containing the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic operation fails.
    pub fn try_wrap(
        key_to_wrap: &PaserkLocal<V>,
        wrapping_key: &PaserkLocal<V>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::wrap::pie_wrap_local_k2k4;

        let header = Self::header();
        let (nonce, ciphertext, tag) =
            pie_wrap_local_k2k4(wrapping_key.as_bytes(), key_to_wrap.as_bytes(), &header)?;

        Ok(Self::new(nonce, ciphertext, tag))
    }

    /// Unwraps the encrypted key using the PIE protocol.
    ///
    /// # Arguments
    ///
    /// * `wrapping_key` - The symmetric key that was used for wrapping
    ///
    /// # Returns
    ///
    /// The original unwrapped symmetric key.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the key is invalid.
    pub fn try_unwrap(&self, wrapping_key: &PaserkLocal<V>) -> PaserkResult<PaserkLocal<V>> {
        use crate::core::operations::wrap::pie_unwrap_local_k2k4;

        let header = Self::header();
        let plaintext =
            pie_unwrap_local_k2k4(wrapping_key.as_bytes(), &self.nonce, &self.ciphertext, &self.tag, &header)?;

        Ok(PaserkLocal::from(plaintext))
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> Display for PaserkLocalWrap<V, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Concatenate nonce || ciphertext || tag
        let mut data = Vec::with_capacity(PIE_NONCE_SIZE + 32 + PIE_TAG_SIZE);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.ciphertext);
        data.extend_from_slice(&self.tag);

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&data);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> Debug for PaserkLocalWrap<V, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkLocalWrap")
            .field("version", &V::PREFIX)
            .field("protocol", &P::PROTOCOL_ID)
            .field("nonce", &"[...]")
            .field("ciphertext", &"[ENCRYPTED]")
            .field("tag", &"[...]")
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> TryFrom<&str> for PaserkLocalWrap<V, P> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let expected_header = Self::header();

        if !paserk.starts_with(&expected_header) {
            // Try to determine what's wrong
            let parts: Vec<&str> = paserk.splitn(4, '.').collect();
            if parts.len() < 4 {
                return Err(PaserkError::InvalidFormat);
            }

            let version = parts[0];
            let type_name = parts[1];
            let protocol = parts[2];

            if version != V::PREFIX {
                return Err(PaserkError::InvalidVersion);
            }

            if type_name != Self::TYPE {
                return Err(PaserkError::InvalidHeader);
            }

            if protocol != P::PROTOCOL_ID {
                return Err(PaserkError::UnsupportedProtocol(protocol.to_string()));
            }

            return Err(PaserkError::InvalidFormat);
        }

        let encoded_data = &paserk[expected_header.len()..];
        let data = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_data)
            .map_err(PaserkError::Base64Decode)?;

        let expected_len = PIE_NONCE_SIZE + 32 + PIE_TAG_SIZE;
        if data.len() != expected_len {
            return Err(PaserkError::InvalidKey);
        }

        let mut nonce = [0u8; PIE_NONCE_SIZE];
        let mut ciphertext = [0u8; 32];
        let mut tag = [0u8; PIE_TAG_SIZE];

        nonce.copy_from_slice(&data[..PIE_NONCE_SIZE]);
        ciphertext.copy_from_slice(&data[PIE_NONCE_SIZE..PIE_NONCE_SIZE + 32]);
        tag.copy_from_slice(&data[PIE_NONCE_SIZE + 32..]);

        Ok(Self::new(nonce, ciphertext, tag))
    }
}

impl<V: PaserkVersion, P: WrapProtocol> TryFrom<String> for PaserkLocalWrap<V, P> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> PartialEq for PaserkLocalWrap<V, P> {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for security
        use subtle::ConstantTimeEq;
        self.nonce.ct_eq(&other.nonce).into()
            && self.ciphertext.ct_eq(&other.ciphertext).into()
            && self.tag.ct_eq(&other.tag).into()
    }
}

impl<V: PaserkVersion, P: WrapProtocol> Eq for PaserkLocalWrap<V, P> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    #[test]
    fn test_header() {
        assert_eq!(PaserkLocalWrap::<K4, Pie>::header(), "k4.local-wrap.pie.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_wrap_unwrap_roundtrip() {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let key_to_wrap = PaserkLocal::<K4>::from([0x13u8; 32]);

        let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&key_to_wrap, &wrapping_key)
            .expect("wrap should succeed");

        let unwrapped = wrapped.try_unwrap(&wrapping_key)
            .expect("unwrap should succeed");

        assert_eq!(unwrapped.as_bytes(), key_to_wrap.as_bytes());
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_serialize_parse_roundtrip() {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let key_to_wrap = PaserkLocal::<K4>::from([0x13u8; 32]);

        let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&key_to_wrap, &wrapping_key)
            .expect("wrap should succeed");

        let serialized = wrapped.to_string();
        assert!(serialized.starts_with("k4.local-wrap.pie."));

        let parsed = PaserkLocalWrap::<K4, Pie>::try_from(serialized.as_str())
            .expect("parse should succeed");

        assert_eq!(wrapped, parsed);

        let unwrapped = parsed.try_unwrap(&wrapping_key)
            .expect("unwrap should succeed");

        assert_eq!(unwrapped.as_bytes(), key_to_wrap.as_bytes());
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unwrap_wrong_key() {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let wrong_key = PaserkLocal::<K4>::from([0x43u8; 32]);
        let key_to_wrap = PaserkLocal::<K4>::from([0x13u8; 32]);

        let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&key_to_wrap, &wrapping_key)
            .expect("wrap should succeed");

        let result = wrapped.try_unwrap(&wrong_key);
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
    }

    #[test]
    fn test_parse_invalid_version() {
        let result = PaserkLocalWrap::<K4, Pie>::try_from(
            "k2.local-wrap.pie.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_parse_invalid_type() {
        let result = PaserkLocalWrap::<K4, Pie>::try_from(
            "k4.secret-wrap.pie.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_parse_invalid_protocol() {
        let result = PaserkLocalWrap::<K4, Pie>::try_from(
            "k4.local-wrap.xyz.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(matches!(result, Err(PaserkError::UnsupportedProtocol(_))));
    }

    #[test]
    fn test_parse_invalid_data_length() {
        let result = PaserkLocalWrap::<K4, Pie>::try_from("k4.local-wrap.pie.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidKey)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let key_to_wrap = PaserkLocal::<K4>::from([0x13u8; 32]);

        let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&key_to_wrap, &wrapping_key)
            .expect("wrap should succeed");

        let debug_str = format!("{wrapped:?}");
        assert!(debug_str.contains("PaserkLocalWrap"));
        assert!(debug_str.contains("k4"));
        assert!(debug_str.contains("pie"));
        assert!(debug_str.contains("[ENCRYPTED]"));
    }
}
