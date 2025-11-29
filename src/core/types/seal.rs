//! PaserkSeal - Symmetric key encrypted with public key.
//!
//! This module provides the `PaserkSeal` type for storing symmetric keys
//! that have been encrypted with a recipient's public key using PKE.
//!
//! Format: `k{version}.seal.{base64url(ephemeral_pk || ciphertext || tag)}`

use core::convert::TryInto;
use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::{PaserkError, PaserkResult};
use crate::core::version::PaserkVersion;

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::operations::pke::{
    EPHEMERAL_PK_SIZE, SEAL_CIPHERTEXT_SIZE, SEAL_DATA_SIZE, SEAL_TAG_SIZE,
};

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::types::{PaserkLocal, PaserkSecret};

/// A symmetric key encrypted with a public key.
///
/// Format: `k{version}.seal.{base64url(ephemeral_pk || ciphertext || tag)}`
///
/// This type represents a symmetric key that has been encrypted using
/// public key encryption (PKE), allowing only the holder of the
/// corresponding secret key to decrypt it.
///
/// # Security
///
/// - Uses X25519 ECDH (K2/K4) for key exchange
/// - Authenticated encryption prevents tampering
/// - Safe to store in PASETO token footers or transmit publicly
///
/// # Example
///
/// ```rust
/// use paserk::core::types::{PaserkLocal, PaserkSecret, PaserkSeal};
/// use paserk::core::version::K4;
/// use ed25519_dalek::SigningKey;
/// use rand_core::OsRng;
///
/// // Generate Ed25519 keypair
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let secret_key = PaserkSecret::<K4>::from(signing_key.to_keypair_bytes());
///
/// // Create a symmetric key to seal
/// let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);
///
/// // Seal with the recipient's public key (derived from secret key)
/// let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key)
///     .expect("seal should succeed");
///
/// // Serialize to PASERK string
/// let paserk_string = sealed.to_string();
///
/// // Parse and unseal
/// let parsed = PaserkSeal::<K4>::try_from(paserk_string.as_str())
///     .expect("parse should succeed");
/// let unsealed = parsed.try_unseal(&secret_key)
///     .expect("unseal should succeed");
/// ```
#[derive(Clone)]
pub struct PaserkSeal<V: PaserkVersion> {
    /// The ephemeral public key (32 bytes for K2/K4).
    #[cfg(any(feature = "k2", feature = "k4"))]
    ephemeral_pk: [u8; EPHEMERAL_PK_SIZE],
    #[cfg(not(any(feature = "k2", feature = "k4")))]
    ephemeral_pk: [u8; 32],

    /// The encrypted key (32 bytes).
    #[cfg(any(feature = "k2", feature = "k4"))]
    ciphertext: [u8; SEAL_CIPHERTEXT_SIZE],
    #[cfg(not(any(feature = "k2", feature = "k4")))]
    ciphertext: [u8; 32],

    /// The authentication tag (32 bytes).
    #[cfg(any(feature = "k2", feature = "k4"))]
    tag: [u8; SEAL_TAG_SIZE],
    #[cfg(not(any(feature = "k2", feature = "k4")))]
    tag: [u8; 32],

    /// Version marker.
    _version: PhantomData<V>,
}

// Constants for when features aren't enabled
#[cfg(not(any(feature = "k2", feature = "k4")))]
const EPHEMERAL_PK_SIZE: usize = 32;
#[cfg(not(any(feature = "k2", feature = "k4")))]
const SEAL_CIPHERTEXT_SIZE: usize = 32;
#[cfg(not(any(feature = "k2", feature = "k4")))]
const SEAL_TAG_SIZE: usize = 32;
#[cfg(not(any(feature = "k2", feature = "k4")))]
const SEAL_DATA_SIZE: usize = 96;

impl<V: PaserkVersion> PaserkSeal<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "seal";

    /// Returns the header for this PASERK type (e.g., "k4.seal.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Creates a new `PaserkSeal` from raw components.
    #[cfg(any(feature = "k2", feature = "k4"))]
    fn new(
        ephemeral_pk: [u8; EPHEMERAL_PK_SIZE],
        ciphertext: [u8; SEAL_CIPHERTEXT_SIZE],
        tag: [u8; SEAL_TAG_SIZE],
    ) -> Self {
        Self {
            ephemeral_pk,
            ciphertext,
            tag,
            _version: PhantomData,
        }
    }

    /// Returns a reference to the ephemeral public key bytes.
    #[must_use]
    #[cfg(any(feature = "k2", feature = "k4"))]
    pub const fn ephemeral_pk(&self) -> &[u8; EPHEMERAL_PK_SIZE] {
        &self.ephemeral_pk
    }

    /// Returns a reference to the ciphertext bytes.
    #[must_use]
    #[cfg(any(feature = "k2", feature = "k4"))]
    pub const fn ciphertext(&self) -> &[u8; SEAL_CIPHERTEXT_SIZE] {
        &self.ciphertext
    }

    /// Returns a reference to the tag bytes.
    #[must_use]
    #[cfg(any(feature = "k2", feature = "k4"))]
    pub const fn tag(&self) -> &[u8; SEAL_TAG_SIZE] {
        &self.tag
    }

    /// Total serialized data size.
    const fn data_size() -> usize {
        SEAL_DATA_SIZE
    }
}

// =============================================================================
// Seal/Unseal operations for K2/K4
// =============================================================================

#[cfg(any(feature = "k2", feature = "k4"))]
impl<V: PaserkVersion + crate::core::version::UsesBlake2b> PaserkSeal<V> {
    /// Seals a symmetric key with a recipient's public key.
    ///
    /// This extracts the X25519 public key from the recipient's Ed25519 secret
    /// key and encrypts the symmetric key so only the secret key holder can
    /// decrypt it.
    ///
    /// # Arguments
    ///
    /// * `key` - The symmetric key to seal
    /// * `recipient_secret` - The recipient's secret key (used to derive public key)
    ///
    /// # Returns
    ///
    /// A new `PaserkSeal` containing the sealed key.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic operation fails.
    pub fn try_seal(key: &PaserkLocal<V>, recipient_secret: &PaserkSecret<V>) -> PaserkResult<Self> {
        use crate::core::operations::pke::seal_k2k4;
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Convert bytes to array reference
        let secret_bytes: &[u8; 64] = recipient_secret
            .as_bytes()
            .try_into()
            .map_err(|_| PaserkError::InvalidKey)?;

        // Convert Ed25519 secret to X25519 public key
        let ed_secret = SigningKey::from_keypair_bytes(secret_bytes)
            .map_err(|_| PaserkError::InvalidKey)?;
        let x25519_secret = StaticSecret::from(ed_secret.to_scalar_bytes());
        let x25519_public: [u8; 32] = PublicKey::from(&x25519_secret).to_bytes();

        let header = Self::header();
        let (ephemeral_pk, ciphertext, tag) =
            seal_k2k4(key.as_bytes(), &x25519_public, &header)?;

        Ok(Self::new(ephemeral_pk, ciphertext, tag))
    }

    /// Unseals the encrypted key using the recipient's secret key.
    ///
    /// # Arguments
    ///
    /// * `recipient_secret` - The recipient's secret key
    ///
    /// # Returns
    ///
    /// The original unsealed symmetric key.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the key is wrong.
    pub fn try_unseal(&self, recipient_secret: &PaserkSecret<V>) -> PaserkResult<PaserkLocal<V>> {
        use crate::core::operations::pke::unseal_k2k4;

        // Convert bytes to array reference
        let secret_bytes: &[u8; 64] = recipient_secret
            .as_bytes()
            .try_into()
            .map_err(|_| PaserkError::InvalidKey)?;

        let header = Self::header();
        let plaintext = unseal_k2k4(
            &self.ephemeral_pk,
            &self.ciphertext,
            &self.tag,
            secret_bytes,
            &header,
        )?;

        Ok(PaserkLocal::from(plaintext))
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkSeal<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Concatenate ephemeral_pk || ciphertext || tag
        let mut data = Vec::with_capacity(Self::data_size());
        data.extend_from_slice(&self.ephemeral_pk);
        data.extend_from_slice(&self.ciphertext);
        data.extend_from_slice(&self.tag);

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&data);
        write!(f, "{}{}", Self::header(), encoded)
    }
}

// =============================================================================
// Debug
// =============================================================================

impl<V: PaserkVersion> Debug for PaserkSeal<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkSeal")
            .field("version", &V::PREFIX)
            .field("ephemeral_pk", &"[...]")
            .field("ciphertext", &"[ENCRYPTED]")
            .field("tag", &"[...]")
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkSeal<V> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let expected_header = Self::header();

        if !paserk.starts_with(&expected_header) {
            let parts: Vec<&str> = paserk.splitn(3, '.').collect();
            if parts.len() < 2 {
                return Err(PaserkError::InvalidFormat);
            }

            let version = parts[0];
            let type_name = parts[1];

            if version != V::PREFIX {
                return Err(PaserkError::InvalidVersion);
            }

            if type_name != Self::TYPE {
                return Err(PaserkError::InvalidHeader);
            }

            return Err(PaserkError::InvalidFormat);
        }

        let encoded_data = &paserk[expected_header.len()..];
        let data = BASE64_URL_SAFE_NO_PAD
            .decode(encoded_data)
            .map_err(PaserkError::Base64Decode)?;

        if data.len() != Self::data_size() {
            return Err(PaserkError::InvalidKey);
        }

        let mut ephemeral_pk = [0u8; EPHEMERAL_PK_SIZE];
        let mut ciphertext = [0u8; SEAL_CIPHERTEXT_SIZE];
        let mut tag = [0u8; SEAL_TAG_SIZE];

        let mut offset = 0;
        ephemeral_pk.copy_from_slice(&data[offset..offset + EPHEMERAL_PK_SIZE]);
        offset += EPHEMERAL_PK_SIZE;
        ciphertext.copy_from_slice(&data[offset..offset + SEAL_CIPHERTEXT_SIZE]);
        offset += SEAL_CIPHERTEXT_SIZE;
        tag.copy_from_slice(&data[offset..]);

        Ok(Self {
            ephemeral_pk,
            ciphertext,
            tag,
            _version: PhantomData,
        })
    }
}

impl<V: PaserkVersion> TryFrom<String> for PaserkSeal<V> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq
// =============================================================================

impl<V: PaserkVersion> PartialEq for PaserkSeal<V> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.ephemeral_pk.ct_eq(&other.ephemeral_pk).into()
            && self.ciphertext.ct_eq(&other.ciphertext).into()
            && self.tag.ct_eq(&other.tag).into()
    }
}

impl<V: PaserkVersion> Eq for PaserkSeal<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    /// Helper function to generate a PaserkSecret for testing.
    /// Uses our rand_core 0.9 OsRng to avoid version conflicts.
    #[cfg(feature = "k4")]
    fn generate_test_secret() -> PaserkResult<PaserkSecret<K4>> {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, TryRngCore};

        // Generate random seed bytes using our OsRng
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).map_err(|_| PaserkError::CryptoError)?;

        // Create Ed25519 signing key from seed
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(PaserkSecret::<K4>::from(signing_key.to_keypair_bytes()))
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkSeal::<K4>::header(), "k4.seal.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_seal_unseal_roundtrip() -> PaserkResult<()> {
        let secret_key = generate_test_secret()?;
        let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key)?;

        let unsealed = sealed.try_unseal(&secret_key)?;

        assert_eq!(unsealed.as_bytes(), local_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_serialize_parse_roundtrip() -> PaserkResult<()> {
        let secret_key = generate_test_secret()?;
        let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key)?;

        let serialized = sealed.to_string();
        assert!(serialized.starts_with("k4.seal."));

        let parsed = PaserkSeal::<K4>::try_from(serialized.as_str())?;

        assert_eq!(sealed, parsed);

        let unsealed = parsed.try_unseal(&secret_key)?;

        assert_eq!(unsealed.as_bytes(), local_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unseal_wrong_key() -> PaserkResult<()> {
        let secret_key1 = generate_test_secret()?;
        let secret_key2 = generate_test_secret()?;

        let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key1)?;

        let result = sealed.try_unseal(&secret_key2);
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn test_parse_invalid_version() {
        let result = PaserkSeal::<K4>::try_from("k2.seal.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_parse_invalid_type() {
        let result = PaserkSeal::<K4>::try_from("k4.local.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_parse_invalid_data_length() {
        let result = PaserkSeal::<K4>::try_from("k4.seal.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidKey)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() -> PaserkResult<()> {
        let secret_key = generate_test_secret()?;
        let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key)?;

        let debug_str = format!("{sealed:?}");
        assert!(debug_str.contains("PaserkSeal"));
        assert!(debug_str.contains("k4"));
        assert!(debug_str.contains("[ENCRYPTED]"));
        Ok(())
    }
}
