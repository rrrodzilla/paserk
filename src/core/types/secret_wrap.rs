//! PaserkSecretWrap - Secret key wrapped with a symmetric key.
//!
//! This module provides the `PaserkSecretWrap` type for storing secret (signing) keys
//! that have been encrypted with a symmetric key using a wrap protocol.
//!
//! Format: `k{version}.secret-wrap.{protocol}.{base64url(tag || nonce || ciphertext)}`

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::{PaserkError, PaserkResult};
use crate::core::operations::wrap::{Pie, WrapProtocol, PIE_NONCE_SIZE, PIE_TAG_SIZE};
use crate::core::types::PaserkSecret;
use crate::core::version::PaserkVersion;

/// PIE nonce size (same for all versions).
const PIE_WRAP_NONCE_SIZE: usize = PIE_NONCE_SIZE;

/// A secret key wrapped with a symmetric key.
///
/// Format: `k{version}.secret-wrap.{protocol}.{base64url(nonce || ciphertext || tag)}`
///
/// This type represents a secret (signing) key that has been encrypted with a
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
/// use paserk::core::types::{PaserkLocal, PaserkSecret, PaserkSecretWrap};
/// use paserk::core::operations::wrap::Pie;
/// use paserk::core::version::K4;
///
/// let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
/// let secret_key = PaserkSecret::<K4>::from([0x13u8; 64]);
///
/// // Wrap the secret key
/// let wrapped = PaserkSecretWrap::<K4, Pie>::try_wrap(&secret_key, &wrapping_key)
///     .expect("wrap should succeed");
///
/// // Serialize to PASERK string
/// let paserk_string = wrapped.to_string();
///
/// // Parse back
/// let parsed = PaserkSecretWrap::<K4, Pie>::try_from(paserk_string.as_str())
///     .expect("parse should succeed");
///
/// // Unwrap to get the original key
/// let unwrapped = parsed.try_unwrap(&wrapping_key)
///     .expect("unwrap should succeed");
/// ```
#[derive(Clone)]
pub struct PaserkSecretWrap<V: PaserkVersion, P: WrapProtocol> {
    /// The random nonce (32 bytes for PIE).
    nonce: [u8; PIE_WRAP_NONCE_SIZE],
    /// The encrypted key (64 bytes for Ed25519 secret keys in K2/K4, 48 bytes for P-384 in K3).
    ciphertext: Vec<u8>,
    /// The authentication tag (32 bytes for K2/K4, 48 bytes for K1/K3).
    tag: Vec<u8>,
    /// Version marker.
    _version: PhantomData<V>,
    /// Protocol marker.
    _protocol: PhantomData<P>,
}

impl<V: PaserkVersion, P: WrapProtocol> PaserkSecretWrap<V, P> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "secret-wrap";

    /// Returns the header for this PASERK type (e.g., "k4.secret-wrap.pie.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.{}.", V::PREFIX, Self::TYPE, P::PROTOCOL_ID)
    }

    /// Creates a new `PaserkSecretWrap` from raw components.
    fn new(nonce: [u8; PIE_WRAP_NONCE_SIZE], ciphertext: Vec<u8>, tag: Vec<u8>) -> Self {
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
    pub const fn nonce(&self) -> &[u8; PIE_WRAP_NONCE_SIZE] {
        &self.nonce
    }

    /// Returns a reference to the ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns a reference to the tag bytes.
    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Returns the expected secret key size for this version.
    fn expected_key_size() -> usize {
        match V::VERSION {
            2 | 4 => 64, // Ed25519 secret key
            3 => 48,     // P-384 secret key
            1 => 0,      // RSA (variable, not supported yet)
            _ => 0,
        }
    }

    /// Returns the expected tag size for this version.
    fn expected_tag_size() -> usize {
        match V::VERSION {
            2 | 4 => PIE_TAG_SIZE, // 32 bytes - BLAKE2b
            1 | 3 => 48,           // 48 bytes - HMAC-SHA384
            _ => PIE_TAG_SIZE,
        }
    }
}

// =============================================================================
// PIE wrapping for K2 (Ed25519 - 64 byte keys, XChaCha20 + BLAKE2b)
// =============================================================================

#[cfg(feature = "k2")]
impl PaserkSecretWrap<crate::core::version::K2, Pie> {
    /// Wraps a secret key using the PIE protocol.
    pub fn try_wrap(
        key_to_wrap: &PaserkSecret<crate::core::version::K2>,
        wrapping_key: &crate::core::types::PaserkLocal<crate::core::version::K2>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::wrap::pie_wrap_secret_k2k4;

        let key_bytes = key_to_wrap.as_bytes();
        if key_bytes.len() != 64 {
            return Err(PaserkError::InvalidKey);
        }

        let mut plaintext = [0u8; 64];
        plaintext.copy_from_slice(key_bytes);

        let header = Self::header();
        let (nonce, ciphertext, tag) =
            pie_wrap_secret_k2k4(wrapping_key.as_bytes(), &plaintext, &header)?;

        Ok(Self::new(nonce, ciphertext.to_vec(), tag.to_vec()))
    }

    /// Unwraps the encrypted key using the PIE protocol.
    pub fn try_unwrap(
        &self,
        wrapping_key: &crate::core::types::PaserkLocal<crate::core::version::K2>,
    ) -> PaserkResult<PaserkSecret<crate::core::version::K2>> {
        use crate::core::operations::wrap::pie_unwrap_secret_k2k4;

        if self.ciphertext.len() != 64 {
            return Err(PaserkError::InvalidKey);
        }
        if self.tag.len() != PIE_TAG_SIZE {
            return Err(PaserkError::InvalidKey);
        }

        let mut ciphertext = [0u8; 64];
        ciphertext.copy_from_slice(&self.ciphertext);
        let mut tag = [0u8; PIE_TAG_SIZE];
        tag.copy_from_slice(&self.tag);

        let header = Self::header();
        let plaintext = pie_unwrap_secret_k2k4(
            wrapping_key.as_bytes(),
            &self.nonce,
            &ciphertext,
            &tag,
            &header,
        )?;

        Ok(PaserkSecret::from(plaintext))
    }
}

// =============================================================================
// PIE wrapping for K4 (Ed25519 - 64 byte keys, XChaCha20 + BLAKE2b)
// =============================================================================

#[cfg(feature = "k4")]
impl PaserkSecretWrap<crate::core::version::K4, Pie> {
    /// Wraps a secret key using the PIE protocol.
    pub fn try_wrap(
        key_to_wrap: &PaserkSecret<crate::core::version::K4>,
        wrapping_key: &crate::core::types::PaserkLocal<crate::core::version::K4>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::wrap::pie_wrap_secret_k2k4;

        let key_bytes = key_to_wrap.as_bytes();
        if key_bytes.len() != 64 {
            return Err(PaserkError::InvalidKey);
        }

        let mut plaintext = [0u8; 64];
        plaintext.copy_from_slice(key_bytes);

        let header = Self::header();
        let (nonce, ciphertext, tag) =
            pie_wrap_secret_k2k4(wrapping_key.as_bytes(), &plaintext, &header)?;

        Ok(Self::new(nonce, ciphertext.to_vec(), tag.to_vec()))
    }

    /// Unwraps the encrypted key using the PIE protocol.
    pub fn try_unwrap(
        &self,
        wrapping_key: &crate::core::types::PaserkLocal<crate::core::version::K4>,
    ) -> PaserkResult<PaserkSecret<crate::core::version::K4>> {
        use crate::core::operations::wrap::pie_unwrap_secret_k2k4;

        if self.ciphertext.len() != 64 {
            return Err(PaserkError::InvalidKey);
        }
        if self.tag.len() != PIE_TAG_SIZE {
            return Err(PaserkError::InvalidKey);
        }

        let mut ciphertext = [0u8; 64];
        ciphertext.copy_from_slice(&self.ciphertext);
        let mut tag = [0u8; PIE_TAG_SIZE];
        tag.copy_from_slice(&self.tag);

        let header = Self::header();
        let plaintext = pie_unwrap_secret_k2k4(
            wrapping_key.as_bytes(),
            &self.nonce,
            &ciphertext,
            &tag,
            &header,
        )?;

        Ok(PaserkSecret::from(plaintext))
    }
}

// =============================================================================
// PIE wrapping for K3 (P-384 - 48 byte keys, AES-256-CTR + HMAC-SHA384)
// =============================================================================

#[cfg(feature = "k3")]
impl PaserkSecretWrap<crate::core::version::K3, Pie> {
    /// Wraps a P-384 secret key using the PIE protocol for K3.
    pub fn try_wrap(
        key_to_wrap: &PaserkSecret<crate::core::version::K3>,
        wrapping_key: &crate::core::types::PaserkLocal<crate::core::version::K3>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::wrap::pie_wrap_secret_k3;

        let key_bytes = key_to_wrap.as_bytes();
        if key_bytes.len() != 48 {
            return Err(PaserkError::InvalidKey);
        }

        let mut plaintext = [0u8; 48];
        plaintext.copy_from_slice(key_bytes);

        let header = Self::header();
        let (nonce, ciphertext, tag) =
            pie_wrap_secret_k3(wrapping_key.as_bytes(), &plaintext, &header)?;

        Ok(Self::new(nonce, ciphertext.to_vec(), tag.to_vec()))
    }

    /// Unwraps the encrypted P-384 secret key using the PIE protocol for K3.
    pub fn try_unwrap(
        &self,
        wrapping_key: &crate::core::types::PaserkLocal<crate::core::version::K3>,
    ) -> PaserkResult<PaserkSecret<crate::core::version::K3>> {
        use crate::core::operations::wrap::{pie_unwrap_secret_k3, PIE_K1K3_TAG_SIZE};

        if self.ciphertext.len() != 48 {
            return Err(PaserkError::InvalidKey);
        }
        if self.tag.len() != PIE_K1K3_TAG_SIZE {
            return Err(PaserkError::InvalidKey);
        }

        let mut ciphertext = [0u8; 48];
        ciphertext.copy_from_slice(&self.ciphertext);
        let mut tag = [0u8; PIE_K1K3_TAG_SIZE];
        tag.copy_from_slice(&self.tag);

        let header = Self::header();
        let plaintext = pie_unwrap_secret_k3(
            wrapping_key.as_bytes(),
            &self.nonce,
            &ciphertext,
            &tag,
            &header,
        )?;

        Ok(PaserkSecret::from(plaintext))
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> Display for PaserkSecretWrap<V, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Concatenate tag || nonce || ciphertext (per PASERK spec)
        let mut data = Vec::with_capacity(self.tag.len() + PIE_WRAP_NONCE_SIZE + self.ciphertext.len());
        data.extend_from_slice(&self.tag);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.ciphertext);

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&data);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> Debug for PaserkSecretWrap<V, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkSecretWrap")
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

impl<V: PaserkVersion, P: WrapProtocol> TryFrom<&str> for PaserkSecretWrap<V, P> {
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

        let expected_key_size = Self::expected_key_size();
        let expected_tag_size = Self::expected_tag_size();
        let expected_len = expected_tag_size + PIE_NONCE_SIZE + expected_key_size;
        if data.len() != expected_len {
            return Err(PaserkError::InvalidKey);
        }

        // Parse tag || nonce || ciphertext (per PASERK spec)
        let tag = data[..expected_tag_size].to_vec();

        let mut nonce = [0u8; PIE_NONCE_SIZE];
        nonce.copy_from_slice(&data[expected_tag_size..expected_tag_size + PIE_NONCE_SIZE]);

        let ciphertext = data[expected_tag_size + PIE_NONCE_SIZE..].to_vec();

        Ok(Self::new(nonce, ciphertext, tag))
    }
}

impl<V: PaserkVersion, P: WrapProtocol> TryFrom<String> for PaserkSecretWrap<V, P> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq
// =============================================================================

impl<V: PaserkVersion, P: WrapProtocol> PartialEq for PaserkSecretWrap<V, P> {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for security
        use subtle::ConstantTimeEq;
        if self.ciphertext.len() != other.ciphertext.len() {
            return false;
        }
        self.nonce.ct_eq(&other.nonce).into()
            && self.ciphertext.ct_eq(&other.ciphertext).into()
            && self.tag.ct_eq(&other.tag).into()
    }
}

impl<V: PaserkVersion, P: WrapProtocol> Eq for PaserkSecretWrap<V, P> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::PaserkLocal;
    use crate::core::version::K4;

    #[test]
    fn test_header() {
        assert_eq!(PaserkSecretWrap::<K4, Pie>::header(), "k4.secret-wrap.pie.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_wrap_unwrap_roundtrip() -> PaserkResult<()> {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let secret_key = PaserkSecret::<K4>::from([0x13u8; 64]);

        let wrapped = PaserkSecretWrap::<K4, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let unwrapped = wrapped.try_unwrap(&wrapping_key)?;

        assert_eq!(unwrapped.as_bytes(), secret_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_serialize_parse_roundtrip() -> PaserkResult<()> {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let secret_key = PaserkSecret::<K4>::from([0x13u8; 64]);

        let wrapped = PaserkSecretWrap::<K4, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let serialized = wrapped.to_string();
        assert!(serialized.starts_with("k4.secret-wrap.pie."));

        let parsed = PaserkSecretWrap::<K4, Pie>::try_from(serialized.as_str())?;

        assert_eq!(wrapped, parsed);

        let unwrapped = parsed.try_unwrap(&wrapping_key)?;

        assert_eq!(unwrapped.as_bytes(), secret_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unwrap_wrong_key() -> PaserkResult<()> {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let wrong_key = PaserkLocal::<K4>::from([0x43u8; 32]);
        let secret_key = PaserkSecret::<K4>::from([0x13u8; 64]);

        let wrapped = PaserkSecretWrap::<K4, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let result = wrapped.try_unwrap(&wrong_key);
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn test_parse_invalid_version() {
        // Need enough base64 data for nonce (32) + ciphertext (64) + tag (32) = 128 bytes
        let result = PaserkSecretWrap::<K4, Pie>::try_from(
            "k2.secret-wrap.pie.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_parse_invalid_type() {
        let result = PaserkSecretWrap::<K4, Pie>::try_from(
            "k4.local-wrap.pie.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_parse_invalid_protocol() {
        let result = PaserkSecretWrap::<K4, Pie>::try_from(
            "k4.secret-wrap.xyz.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(matches!(result, Err(PaserkError::UnsupportedProtocol(_))));
    }

    #[test]
    fn test_parse_invalid_data_length() {
        let result = PaserkSecretWrap::<K4, Pie>::try_from("k4.secret-wrap.pie.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidKey)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() -> PaserkResult<()> {
        let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let secret_key = PaserkSecret::<K4>::from([0x13u8; 64]);

        let wrapped = PaserkSecretWrap::<K4, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let debug_str = format!("{wrapped:?}");
        assert!(debug_str.contains("PaserkSecretWrap"));
        assert!(debug_str.contains("k4"));
        assert!(debug_str.contains("pie"));
        assert!(debug_str.contains("[ENCRYPTED]"));
        Ok(())
    }

    // =============================================================================
    // K3 Secret Wrap Tests (P-384)
    // =============================================================================

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_header() {
        use crate::core::version::K3;
        assert_eq!(PaserkSecretWrap::<K3, Pie>::header(), "k3.secret-wrap.pie.");
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_wrap_unwrap_roundtrip() -> PaserkResult<()> {
        use crate::core::version::K3;

        let wrapping_key = PaserkLocal::<K3>::from([0x42u8; 32]);
        let secret_key = PaserkSecret::<K3>::from([0x13u8; 48]); // P-384 key is 48 bytes

        let wrapped = PaserkSecretWrap::<K3, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let unwrapped = wrapped.try_unwrap(&wrapping_key)?;

        assert_eq!(unwrapped.as_bytes(), secret_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_serialize_parse_roundtrip() -> PaserkResult<()> {
        use crate::core::version::K3;

        let wrapping_key = PaserkLocal::<K3>::from([0x42u8; 32]);
        let secret_key = PaserkSecret::<K3>::from([0x13u8; 48]);

        let wrapped = PaserkSecretWrap::<K3, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let serialized = wrapped.to_string();
        assert!(serialized.starts_with("k3.secret-wrap.pie."));

        let parsed = PaserkSecretWrap::<K3, Pie>::try_from(serialized.as_str())?;

        assert_eq!(wrapped, parsed);

        let unwrapped = parsed.try_unwrap(&wrapping_key)?;

        assert_eq!(unwrapped.as_bytes(), secret_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_unwrap_wrong_key() -> PaserkResult<()> {
        use crate::core::version::K3;

        let wrapping_key = PaserkLocal::<K3>::from([0x42u8; 32]);
        let wrong_key = PaserkLocal::<K3>::from([0x43u8; 32]);
        let secret_key = PaserkSecret::<K3>::from([0x13u8; 48]);

        let wrapped = PaserkSecretWrap::<K3, Pie>::try_wrap(&secret_key, &wrapping_key)?;

        let result = wrapped.try_unwrap(&wrong_key);
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }
}
