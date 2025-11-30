//! `PaserkSeal` - Symmetric key encrypted with public key.
//!
//! This module provides the `PaserkSeal` type for storing symmetric keys
//! that have been encrypted with a recipient's public key using PKE.
//!
//! Format varies by version:
//! - K1: `k1.seal.{base64url(tag || edk || c)}`
//! - K2/K3/K4: `k{version}.seal.{base64url(ephemeral_pk || ciphertext || tag)}`
//!
//! # Version Differences
//!
//! - K1: Uses RSA-4096 KEM + AES-256-CTR + HMAC-SHA384 (512-byte RSA ciphertext, 48-byte tag)
//! - K2/K4: Uses X25519 (32-byte ephemeral key) + `BLAKE2b` (32-byte tag)
//! - K3: Uses P-384 (49-byte compressed ephemeral key) + HMAC-SHA384 (48-byte tag)

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::{PaserkError, PaserkResult};
use crate::core::version::PaserkVersion;

#[cfg(any(feature = "k1-insecure", feature = "k2", feature = "k3", feature = "k4"))]
use crate::core::types::PaserkLocal;

#[cfg(any(feature = "k2", feature = "k3", feature = "k4"))]
use crate::core::types::PaserkSecret;

/// A symmetric key encrypted with a public key.
///
/// Format varies by version:
/// - K1: `k1.seal.{base64url(tag || edk || c)}`
/// - K2/K3/K4: `k{version}.seal.{base64url(ephemeral_pk || ciphertext || tag)}`
///
/// This type represents a symmetric key that has been encrypted using
/// public key encryption (PKE), allowing only the holder of the
/// corresponding secret key to decrypt it.
///
/// # Version Differences
///
/// - K1: RSA-4096 KEM + AES-256-CTR + HMAC-SHA384 (512-byte RSA ciphertext, 48-byte tag)
/// - K2/K4: X25519 ECDH + `XChaCha20` + `BLAKE2b` (32-byte ephemeral, 32-byte tag)
/// - K3: P-384 ECDH + AES-256-CTR + HMAC-SHA384 (49-byte ephemeral, 48-byte tag)
///
/// # Security
///
/// - Authenticated encryption prevents tampering
/// - Safe to store in PASETO token footers or transmit publicly
///
/// # Example
///
/// ```rust,ignore
/// use paserk::core::types::{PaserkLocal, PaserkSecret, PaserkSeal};
/// use paserk::core::version::K4;
/// use ed25519_dalek::SigningKey;
///
/// // Create Ed25519 keypair from seed bytes
/// let seed = [0u8; 32]; // Use secure random bytes in production!
/// let signing_key = SigningKey::from_bytes(&seed);
/// let secret_key = PaserkSecret::<K4>::from(signing_key.to_keypair_bytes());
///
/// // Create a symmetric key to seal
/// let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);
///
/// // Seal with the recipient's public key (derived from secret key)
/// let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key)?;
///
/// // Serialize to PASERK string
/// let paserk_string = sealed.to_string();
///
/// // Parse and unseal
/// let parsed = PaserkSeal::<K4>::try_from(paserk_string.as_str())?;
/// let unsealed = parsed.try_unseal(&secret_key)?;
/// # Ok::<(), paserk::PaserkError>(())
/// ```
#[derive(Clone)]
pub struct PaserkSeal<V: PaserkVersion> {
    /// For K2/K3/K4: ephemeral public key (32/49/32 bytes).
    /// For K1: RSA ciphertext (512 bytes).
    ephemeral_pk_or_rsa_ct: Vec<u8>,
    /// The encrypted key (32 bytes for all versions).
    ciphertext: Vec<u8>,
    /// The authentication tag (48 bytes for K1/K3, 32 bytes for K2/K4).
    tag: Vec<u8>,
    /// Version marker.
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkSeal<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "seal";

    /// Returns the header for this PASERK type (e.g., "k4.seal.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Creates a new `PaserkSeal` from raw components.
    ///
    /// For K1: `ephemeral_pk_or_rsa_ct` is the RSA ciphertext.
    /// For K2/K3/K4: `ephemeral_pk_or_rsa_ct` is the ephemeral public key.
    const fn new(ephemeral_pk_or_rsa_ct: Vec<u8>, ciphertext: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            ephemeral_pk_or_rsa_ct,
            ciphertext,
            tag,
            _version: PhantomData,
        }
    }

    /// Returns a reference to the ephemeral public key bytes (K2/K3/K4)
    /// or RSA ciphertext bytes (K1).
    #[must_use]
    pub fn ephemeral_pk(&self) -> &[u8] {
        &self.ephemeral_pk_or_rsa_ct
    }

    /// Returns a reference to the RSA ciphertext bytes (K1 only).
    /// For other versions, this returns the ephemeral public key.
    #[must_use]
    pub fn rsa_ciphertext(&self) -> &[u8] {
        &self.ephemeral_pk_or_rsa_ct
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

    /// Returns the expected ephemeral public key size (K2/K3/K4) or RSA ciphertext size (K1).
    const fn expected_ephemeral_pk_size() -> usize {
        match V::VERSION {
            1 => 512, // RSA-4096 ciphertext
            3 => 49,  // P-384 compressed SEC1
            _ => 32,  // X25519 (K2, K4)
        }
    }

    /// Returns the expected tag size for this version.
    const fn expected_tag_size() -> usize {
        match V::VERSION {
            1 | 3 => 48, // HMAC-SHA384
            _ => 32,     // BLAKE2b (K2, K4)
        }
    }

    /// Total serialized data size.
    const fn data_size() -> usize {
        Self::expected_ephemeral_pk_size() + 32 + Self::expected_tag_size()
    }
}

// =============================================================================
// Seal/Unseal operations for K1 (RSA-4096 KEM + AES-256-CTR + HMAC-SHA384)
// =============================================================================

#[cfg(feature = "k1-insecure")]
#[allow(deprecated)]
impl PaserkSeal<crate::core::version::K1> {
    /// Seals a symmetric key with a recipient's RSA-4096 public key.
    ///
    /// The public key must have a 4096-bit modulus and exponent 65537.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or the cryptographic operation fails.
    pub fn try_seal_with_rsa(
        key: &PaserkLocal<crate::core::version::K1>,
        recipient_pk: &rsa::RsaPublicKey,
    ) -> PaserkResult<Self> {
        use crate::core::operations::pke::seal_k1;

        let header = Self::header();
        let (tag, edk, c) = seal_k1(key.as_bytes(), recipient_pk, &header)?;

        // For K1, we store: c in ephemeral_pk_or_rsa_ct, edk in ciphertext, tag in tag
        Ok(Self::new(c.to_vec(), edk.to_vec(), tag.to_vec()))
    }

    /// Unseals the encrypted key using the recipient's RSA-4096 secret key.
    ///
    /// The secret key must have a 4096-bit modulus.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or authentication fails.
    pub fn try_unseal_with_rsa(
        &self,
        recipient_sk: &rsa::RsaPrivateKey,
    ) -> PaserkResult<PaserkLocal<crate::core::version::K1>> {
        use crate::core::operations::pke::{
            unseal_k1, K1_RSA_CIPHERTEXT_SIZE, K1_SEAL_CIPHERTEXT_SIZE, K1_SEAL_TAG_SIZE,
        };

        if self.ephemeral_pk_or_rsa_ct.len() != K1_RSA_CIPHERTEXT_SIZE
            || self.ciphertext.len() != K1_SEAL_CIPHERTEXT_SIZE
            || self.tag.len() != K1_SEAL_TAG_SIZE
        {
            return Err(PaserkError::InvalidKey);
        }

        let mut c = [0u8; K1_RSA_CIPHERTEXT_SIZE];
        let mut edk = [0u8; K1_SEAL_CIPHERTEXT_SIZE];
        let mut tag = [0u8; K1_SEAL_TAG_SIZE];

        c.copy_from_slice(&self.ephemeral_pk_or_rsa_ct);
        edk.copy_from_slice(&self.ciphertext);
        tag.copy_from_slice(&self.tag);

        let header = Self::header();
        let plaintext = unseal_k1(&tag, &edk, &c, recipient_sk, &header)?;

        Ok(PaserkLocal::from(plaintext))
    }
}

// =============================================================================
// Seal/Unseal operations for K2 (X25519 + BLAKE2b)
// =============================================================================

#[cfg(feature = "k2")]
impl PaserkSeal<crate::core::version::K2> {
    /// Seals a symmetric key with a recipient's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or the cryptographic operation fails.
    pub fn try_seal(
        key: &PaserkLocal<crate::core::version::K2>,
        recipient_secret: &PaserkSecret<crate::core::version::K2>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::pke::seal_k2k4;
        use core::convert::TryInto;
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret_bytes: &[u8; 64] = recipient_secret
            .as_bytes()
            .try_into()
            .map_err(|_| PaserkError::InvalidKey)?;

        let ed_secret =
            SigningKey::from_keypair_bytes(secret_bytes).map_err(|_| PaserkError::InvalidKey)?;
        let x25519_secret = StaticSecret::from(ed_secret.to_scalar_bytes());
        let x25519_public: [u8; 32] = PublicKey::from(&x25519_secret).to_bytes();

        let header = Self::header();
        // seal_k2k4 returns (tag, ephemeral_pk, ciphertext)
        let (tag, ephemeral_pk, ciphertext) = seal_k2k4(key.as_bytes(), &x25519_public, &header)?;

        // Store in the order needed for serialization: (epk, ciphertext, tag)
        Ok(Self::new(
            ephemeral_pk.to_vec(),
            ciphertext.to_vec(),
            tag.to_vec(),
        ))
    }

    /// Unseals the encrypted key using the recipient's secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or authentication fails.
    pub fn try_unseal(
        &self,
        recipient_secret: &PaserkSecret<crate::core::version::K2>,
    ) -> PaserkResult<PaserkLocal<crate::core::version::K2>> {
        use crate::core::operations::pke::unseal_k2k4;
        use core::convert::TryInto;

        let secret_bytes: &[u8; 64] = recipient_secret
            .as_bytes()
            .try_into()
            .map_err(|_| PaserkError::InvalidKey)?;

        if self.ephemeral_pk_or_rsa_ct.len() != 32
            || self.ciphertext.len() != 32
            || self.tag.len() != 32
        {
            return Err(PaserkError::InvalidKey);
        }

        let mut ephemeral_pk = [0u8; 32];
        let mut ciphertext = [0u8; 32];
        let mut tag = [0u8; 32];
        ephemeral_pk.copy_from_slice(&self.ephemeral_pk_or_rsa_ct);
        ciphertext.copy_from_slice(&self.ciphertext);
        tag.copy_from_slice(&self.tag);

        let header = Self::header();
        // unseal_k2k4 expects (tag, ephemeral_pk, ciphertext)
        let plaintext = unseal_k2k4(&tag, &ephemeral_pk, &ciphertext, secret_bytes, &header)?;

        Ok(PaserkLocal::from(plaintext))
    }
}

// =============================================================================
// Seal/Unseal operations for K4 (X25519 + BLAKE2b)
// =============================================================================

#[cfg(feature = "k4")]
impl PaserkSeal<crate::core::version::K4> {
    /// Seals a symmetric key with a recipient's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or the cryptographic operation fails.
    pub fn try_seal(
        key: &PaserkLocal<crate::core::version::K4>,
        recipient_secret: &PaserkSecret<crate::core::version::K4>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::pke::seal_k2k4;
        use core::convert::TryInto;
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret_bytes: &[u8; 64] = recipient_secret
            .as_bytes()
            .try_into()
            .map_err(|_| PaserkError::InvalidKey)?;

        let ed_secret =
            SigningKey::from_keypair_bytes(secret_bytes).map_err(|_| PaserkError::InvalidKey)?;
        let x25519_secret = StaticSecret::from(ed_secret.to_scalar_bytes());
        let x25519_public: [u8; 32] = PublicKey::from(&x25519_secret).to_bytes();

        let header = Self::header();
        // seal_k2k4 returns (tag, ephemeral_pk, ciphertext)
        let (tag, ephemeral_pk, ciphertext) = seal_k2k4(key.as_bytes(), &x25519_public, &header)?;

        // Store in the order needed for serialization: (epk, ciphertext, tag)
        Ok(Self::new(
            ephemeral_pk.to_vec(),
            ciphertext.to_vec(),
            tag.to_vec(),
        ))
    }

    /// Unseals the encrypted key using the recipient's secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or authentication fails.
    pub fn try_unseal(
        &self,
        recipient_secret: &PaserkSecret<crate::core::version::K4>,
    ) -> PaserkResult<PaserkLocal<crate::core::version::K4>> {
        use crate::core::operations::pke::unseal_k2k4;
        use core::convert::TryInto;

        let secret_bytes: &[u8; 64] = recipient_secret
            .as_bytes()
            .try_into()
            .map_err(|_| PaserkError::InvalidKey)?;

        if self.ephemeral_pk_or_rsa_ct.len() != 32
            || self.ciphertext.len() != 32
            || self.tag.len() != 32
        {
            return Err(PaserkError::InvalidKey);
        }

        let mut ephemeral_pk = [0u8; 32];
        let mut ciphertext = [0u8; 32];
        let mut tag = [0u8; 32];
        ephemeral_pk.copy_from_slice(&self.ephemeral_pk_or_rsa_ct);
        ciphertext.copy_from_slice(&self.ciphertext);
        tag.copy_from_slice(&self.tag);

        let header = Self::header();
        // unseal_k2k4 expects (tag, ephemeral_pk, ciphertext)
        let plaintext = unseal_k2k4(&tag, &ephemeral_pk, &ciphertext, secret_bytes, &header)?;

        Ok(PaserkLocal::from(plaintext))
    }
}

// =============================================================================
// Seal/Unseal operations for K3 (P-384 ECDH + AES-256-CTR + HMAC-SHA384)
// =============================================================================

#[cfg(feature = "k3")]
impl PaserkSeal<crate::core::version::K3> {
    /// Seals a symmetric key with a recipient's P-384 public key.
    ///
    /// This extracts the P-384 public key from the recipient's secret key
    /// and encrypts the symmetric key so only the secret key holder can
    /// decrypt it.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or the cryptographic operation fails.
    pub fn try_seal(
        key: &PaserkLocal<crate::core::version::K3>,
        recipient_secret: &PaserkSecret<crate::core::version::K3>,
    ) -> PaserkResult<Self> {
        use crate::core::operations::pke::{seal_k3, K3_EPHEMERAL_PK_SIZE};
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        use p384::SecretKey;

        // K3 secret key is 48 bytes (P-384 scalar)
        let secret_bytes = recipient_secret.as_bytes();
        if secret_bytes.len() != 48 {
            return Err(PaserkError::InvalidKey);
        }

        // Parse the secret key and derive public key
        let secret_key =
            SecretKey::from_slice(secret_bytes).map_err(|_| PaserkError::InvalidKey)?;
        let public_key = secret_key.public_key();
        let public_point = public_key.to_encoded_point(true);
        let mut recipient_pk = [0u8; K3_EPHEMERAL_PK_SIZE];
        recipient_pk.copy_from_slice(public_point.as_bytes());

        let header = Self::header();
        let (ephemeral_pk, ciphertext, tag) = seal_k3(key.as_bytes(), &recipient_pk, &header)?;

        Ok(Self::new(
            ephemeral_pk.to_vec(),
            ciphertext.to_vec(),
            tag.to_vec(),
        ))
    }

    /// Unseals the encrypted key using the recipient's P-384 secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid or authentication fails.
    pub fn try_unseal(
        &self,
        recipient_secret: &PaserkSecret<crate::core::version::K3>,
    ) -> PaserkResult<PaserkLocal<crate::core::version::K3>> {
        use crate::core::operations::pke::{
            unseal_k3, K3_EPHEMERAL_PK_SIZE, K3_SEAL_CIPHERTEXT_SIZE, K3_SEAL_TAG_SIZE,
        };

        // K3 secret key is 48 bytes (P-384 scalar)
        let secret_bytes = recipient_secret.as_bytes();
        if secret_bytes.len() != 48 {
            return Err(PaserkError::InvalidKey);
        }

        if self.ephemeral_pk_or_rsa_ct.len() != K3_EPHEMERAL_PK_SIZE
            || self.ciphertext.len() != K3_SEAL_CIPHERTEXT_SIZE
            || self.tag.len() != K3_SEAL_TAG_SIZE
        {
            return Err(PaserkError::InvalidKey);
        }

        let mut ephemeral_pk = [0u8; K3_EPHEMERAL_PK_SIZE];
        let mut ciphertext = [0u8; K3_SEAL_CIPHERTEXT_SIZE];
        let mut tag = [0u8; K3_SEAL_TAG_SIZE];
        let mut secret_key = [0u8; 48];

        ephemeral_pk.copy_from_slice(&self.ephemeral_pk_or_rsa_ct);
        ciphertext.copy_from_slice(&self.ciphertext);
        tag.copy_from_slice(&self.tag);
        secret_key.copy_from_slice(secret_bytes);

        let header = Self::header();
        let plaintext = unseal_k3(&ephemeral_pk, &ciphertext, &tag, &secret_key, &header)?;

        Ok(PaserkLocal::from(plaintext))
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkSeal<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = Vec::with_capacity(
            self.ephemeral_pk_or_rsa_ct.len() + self.ciphertext.len() + self.tag.len(),
        );

        // All formats start with tag
        // K1 format: tag || edk || c
        // K2/K3/K4 format: tag || ephemeral_pk || ciphertext (per PASERK spec)
        data.extend_from_slice(&self.tag);
        if V::VERSION == 1 {
            data.extend_from_slice(&self.ciphertext);
            data.extend_from_slice(&self.ephemeral_pk_or_rsa_ct);
        } else {
            data.extend_from_slice(&self.ephemeral_pk_or_rsa_ct);
            data.extend_from_slice(&self.ciphertext);
        }

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

        let ephemeral_pk_size = Self::expected_ephemeral_pk_size();
        let ciphertext_size = 32;
        let tag_size = Self::expected_tag_size();

        // All formats start with tag
        // K1 format: tag || edk || c
        // K2/K3/K4 format: tag || ephemeral_pk || ciphertext (per PASERK spec)
        let tag = data[..tag_size].to_vec();
        let (ephemeral_pk_or_rsa_ct, ciphertext) = if V::VERSION == 1 {
            let ciphertext = data[tag_size..tag_size + ciphertext_size].to_vec();
            let rsa_ct = data[tag_size + ciphertext_size..].to_vec();
            (rsa_ct, ciphertext)
        } else {
            let ephemeral_pk = data[tag_size..tag_size + ephemeral_pk_size].to_vec();
            let ciphertext = data[tag_size + ephemeral_pk_size..].to_vec();
            (ephemeral_pk, ciphertext)
        };

        Ok(Self::new(ephemeral_pk_or_rsa_ct, ciphertext, tag))
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
        if self.ephemeral_pk_or_rsa_ct.len() != other.ephemeral_pk_or_rsa_ct.len()
            || self.ciphertext.len() != other.ciphertext.len()
            || self.tag.len() != other.tag.len()
        {
            return false;
        }
        self.ephemeral_pk_or_rsa_ct
            .ct_eq(&other.ephemeral_pk_or_rsa_ct)
            .into()
            && self.ciphertext.ct_eq(&other.ciphertext).into()
            && self.tag.ct_eq(&other.tag).into()
    }
}

impl<V: PaserkVersion> Eq for PaserkSeal<V> {}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    /// Helper function to generate a `PaserkSecret` for testing.
    #[cfg(feature = "k4")]
    fn generate_test_secret() -> PaserkResult<PaserkSecret<K4>> {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, TryRngCore};

        let mut seed = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| PaserkError::CryptoError)?;

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

    // =========================================================================
    // K3 Seal Tests (P-384)
    // =========================================================================

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_header() {
        use crate::core::version::K3;
        assert_eq!(PaserkSeal::<K3>::header(), "k3.seal.");
    }

    #[cfg(feature = "k3")]
    fn generate_k3_test_secret() -> PaserkSecret<crate::core::version::K3> {
        use p384::elliptic_curve::rand_core::OsRng as P384OsRng;
        use p384::SecretKey;

        let secret_key = SecretKey::random(&mut P384OsRng);
        let secret_bytes = secret_key.to_bytes();
        let mut sk = [0u8; 48];
        sk.copy_from_slice(&secret_bytes);

        PaserkSecret::<crate::core::version::K3>::from(sk)
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_seal_unseal_roundtrip() -> PaserkResult<()> {
        use crate::core::version::K3;

        let secret_key = generate_k3_test_secret();
        let local_key = PaserkLocal::<K3>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K3>::try_seal(&local_key, &secret_key)?;

        let unsealed = sealed.try_unseal(&secret_key)?;

        assert_eq!(unsealed.as_bytes(), local_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_serialize_parse_roundtrip() -> PaserkResult<()> {
        use crate::core::version::K3;

        let secret_key = generate_k3_test_secret();
        let local_key = PaserkLocal::<K3>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K3>::try_seal(&local_key, &secret_key)?;

        let serialized = sealed.to_string();
        assert!(serialized.starts_with("k3.seal."));

        let parsed = PaserkSeal::<K3>::try_from(serialized.as_str())?;

        assert_eq!(sealed, parsed);

        let unsealed = parsed.try_unseal(&secret_key)?;

        assert_eq!(unsealed.as_bytes(), local_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_unseal_wrong_key() -> PaserkResult<()> {
        use crate::core::version::K3;

        let secret_key1 = generate_k3_test_secret();
        let secret_key2 = generate_k3_test_secret();

        let local_key = PaserkLocal::<K3>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K3>::try_seal(&local_key, &secret_key1)?;

        let result = sealed.try_unseal(&secret_key2);
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_ephemeral_pk_size() -> PaserkResult<()> {
        use crate::core::version::K3;

        let secret_key = generate_k3_test_secret();
        let local_key = PaserkLocal::<K3>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K3>::try_seal(&local_key, &secret_key)?;

        // K3 uses P-384 compressed format: 49 bytes
        assert_eq!(sealed.ephemeral_pk().len(), 49);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_k3_tag_size() -> PaserkResult<()> {
        use crate::core::version::K3;

        let secret_key = generate_k3_test_secret();
        let local_key = PaserkLocal::<K3>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K3>::try_seal(&local_key, &secret_key)?;

        // K3 uses HMAC-SHA384: 48 bytes
        assert_eq!(sealed.tag().len(), 48);
        Ok(())
    }

    // =========================================================================
    // K1 Seal Tests (RSA-4096 KEM)
    // =========================================================================

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_header() {
        use crate::core::version::K1;
        assert_eq!(PaserkSeal::<K1>::header(), "k1.seal.");
    }

    #[cfg(feature = "k1-insecure")]
    fn generate_k1_test_keypair() -> PaserkResult<(rsa::RsaPrivateKey, rsa::RsaPublicKey)> {
        use rsa::RsaPrivateKey;

        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 4096).map_err(|_| PaserkError::CryptoError)?;
        let public_key = private_key.to_public_key();

        Ok((private_key, public_key))
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_seal_unseal_roundtrip() -> PaserkResult<()> {
        use crate::core::version::K1;

        let (private_key, public_key) = generate_k1_test_keypair()?;
        let local_key = PaserkLocal::<K1>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K1>::try_seal_with_rsa(&local_key, &public_key)?;

        let unsealed = sealed.try_unseal_with_rsa(&private_key)?;

        assert_eq!(unsealed.as_bytes(), local_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_serialize_parse_roundtrip() -> PaserkResult<()> {
        use crate::core::version::K1;

        let (private_key, public_key) = generate_k1_test_keypair()?;
        let local_key = PaserkLocal::<K1>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K1>::try_seal_with_rsa(&local_key, &public_key)?;

        let serialized = sealed.to_string();
        assert!(serialized.starts_with("k1.seal."));

        let parsed = PaserkSeal::<K1>::try_from(serialized.as_str())?;

        assert_eq!(sealed, parsed);

        let unsealed = parsed.try_unseal_with_rsa(&private_key)?;

        assert_eq!(unsealed.as_bytes(), local_key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_unseal_wrong_key() -> PaserkResult<()> {
        use crate::core::version::K1;

        let (_, public_key1) = generate_k1_test_keypair()?;
        let (private_key2, _) = generate_k1_test_keypair()?;

        let local_key = PaserkLocal::<K1>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K1>::try_seal_with_rsa(&local_key, &public_key1)?;

        let result = sealed.try_unseal_with_rsa(&private_key2);
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_rsa_ciphertext_size() -> PaserkResult<()> {
        use crate::core::version::K1;

        let (_, public_key) = generate_k1_test_keypair()?;
        let local_key = PaserkLocal::<K1>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K1>::try_seal_with_rsa(&local_key, &public_key)?;

        // RSA-4096 = 512 bytes
        assert_eq!(sealed.rsa_ciphertext().len(), 512);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_tag_size() -> PaserkResult<()> {
        use crate::core::version::K1;

        let (_, public_key) = generate_k1_test_keypair()?;
        let local_key = PaserkLocal::<K1>::from([0x42u8; 32]);

        let sealed = PaserkSeal::<K1>::try_seal_with_rsa(&local_key, &public_key)?;

        // HMAC-SHA384 = 48 bytes
        assert_eq!(sealed.tag().len(), 48);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_k1_data_size() {
        use crate::core::version::K1;
        // K1: tag (48) + edk (32) + c (512) = 592 bytes
        assert_eq!(PaserkSeal::<K1>::data_size(), 592);
    }
}
