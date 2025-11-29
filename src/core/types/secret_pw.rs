//! PaserkSecretPw - Secret key wrapped with a password.
//!
//! This module provides the `PaserkSecretPw` type for storing secret (signing) keys
//! that have been encrypted with a password using PBKW.
//!
//! Format: `k{version}.secret-pw.{base64url(salt || nonce || ciphertext || tag)}`

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::{PaserkError, PaserkResult};
use crate::core::version::PaserkVersion;

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::operations::pbkw::{
    Argon2Params, ARGON2_SALT_SIZE, PBKW_TAG_SIZE, XCHACHA20_NONCE_SIZE,
};

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::types::PaserkSecret;

/// A secret key wrapped with a password.
///
/// Format: `k{version}.secret-pw.{base64url(salt || nonce || ciphertext || tag)}`
///
/// This type represents a secret (signing) key that has been encrypted with a
/// password using password-based key wrapping (PBKW).
///
/// # Security
///
/// - Uses Argon2id (K2/K4) for password stretching
/// - Authenticated encryption prevents tampering
/// - Safe to store in files or databases
///
/// # Example
///
/// ```rust
/// use paserk::core::types::{PaserkSecret, PaserkSecretPw};
/// use paserk::core::operations::pbkw::Argon2Params;
/// use paserk::core::version::K4;
///
/// let key = PaserkSecret::<K4>::from([0x42u8; 64]);
///
/// // Wrap with password
/// let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, b"password", Argon2Params::moderate())
///     .expect("wrap should succeed");
///
/// // Serialize
/// let paserk_string = wrapped.to_string();
///
/// // Parse and unwrap
/// let parsed = PaserkSecretPw::<K4>::try_from(paserk_string.as_str())
///     .expect("parse should succeed");
/// let unwrapped = parsed.try_unwrap(b"password", Argon2Params::moderate())
///     .expect("unwrap should succeed");
/// ```
#[derive(Clone)]
pub struct PaserkSecretPw<V: PaserkVersion> {
    /// The Argon2 salt (16 bytes).
    #[cfg(any(feature = "k2", feature = "k4"))]
    salt: [u8; ARGON2_SALT_SIZE],
    #[cfg(not(any(feature = "k2", feature = "k4")))]
    salt: [u8; 16],

    /// The XChaCha20 nonce (24 bytes).
    #[cfg(any(feature = "k2", feature = "k4"))]
    nonce: [u8; XCHACHA20_NONCE_SIZE],
    #[cfg(not(any(feature = "k2", feature = "k4")))]
    nonce: [u8; 24],

    /// The encrypted key (64 bytes for Ed25519).
    ciphertext: Vec<u8>,

    /// The authentication tag (32 bytes).
    #[cfg(any(feature = "k2", feature = "k4"))]
    tag: [u8; PBKW_TAG_SIZE],
    #[cfg(not(any(feature = "k2", feature = "k4")))]
    tag: [u8; 32],

    /// Version marker.
    _version: PhantomData<V>,
}

// Constants for when features aren't enabled
#[cfg(not(any(feature = "k2", feature = "k4")))]
const ARGON2_SALT_SIZE: usize = 16;
#[cfg(not(any(feature = "k2", feature = "k4")))]
const XCHACHA20_NONCE_SIZE: usize = 24;
#[cfg(not(any(feature = "k2", feature = "k4")))]
const PBKW_TAG_SIZE: usize = 32;

impl<V: PaserkVersion> PaserkSecretPw<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "secret-pw";

    /// Returns the header for this PASERK type (e.g., "k4.secret-pw.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Creates a new `PaserkSecretPw` from raw components.
    #[cfg(any(feature = "k2", feature = "k4"))]
    fn new(
        salt: [u8; ARGON2_SALT_SIZE],
        nonce: [u8; XCHACHA20_NONCE_SIZE],
        ciphertext: Vec<u8>,
        tag: [u8; PBKW_TAG_SIZE],
    ) -> Self {
        Self {
            salt,
            nonce,
            ciphertext,
            tag,
            _version: PhantomData,
        }
    }

    /// Returns a reference to the salt bytes.
    #[must_use]
    #[cfg(any(feature = "k2", feature = "k4"))]
    pub const fn salt(&self) -> &[u8; ARGON2_SALT_SIZE] {
        &self.salt
    }

    /// Returns a reference to the nonce bytes.
    #[must_use]
    #[cfg(any(feature = "k2", feature = "k4"))]
    pub const fn nonce(&self) -> &[u8; XCHACHA20_NONCE_SIZE] {
        &self.nonce
    }

    /// Returns a reference to the ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns a reference to the tag bytes.
    #[must_use]
    #[cfg(any(feature = "k2", feature = "k4"))]
    pub const fn tag(&self) -> &[u8; PBKW_TAG_SIZE] {
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
}

// =============================================================================
// PBKW wrapping for K2/K4
// =============================================================================

#[cfg(any(feature = "k2", feature = "k4"))]
impl<V: PaserkVersion + crate::core::version::UsesArgon2> PaserkSecretPw<V> {
    /// Wraps a secret key with a password using PBKW.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to wrap
    /// * `password` - The password to use for wrapping
    /// * `params` - Argon2id parameters
    ///
    /// # Returns
    ///
    /// A new `PaserkSecretPw` containing the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic operation fails.
    pub fn try_wrap(
        key: &PaserkSecret<V>,
        password: &[u8],
        params: Argon2Params,
    ) -> PaserkResult<Self> {
        use crate::core::operations::pbkw::pbkw_wrap_secret_k2k4;

        let key_bytes = key.as_bytes();
        if key_bytes.len() != 64 {
            return Err(PaserkError::InvalidKey);
        }

        let mut plaintext = [0u8; 64];
        plaintext.copy_from_slice(key_bytes);

        let header = Self::header();
        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_secret_k2k4(&plaintext, password, &params, &header)?;

        Ok(Self::new(salt, nonce, ciphertext.to_vec(), tag))
    }

    /// Unwraps the encrypted key using the password.
    ///
    /// # Arguments
    ///
    /// * `password` - The password used for wrapping
    /// * `params` - Argon2id parameters (must match those used for wrapping)
    ///
    /// # Returns
    ///
    /// The original unwrapped secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the password is wrong.
    pub fn try_unwrap(
        &self,
        password: &[u8],
        params: Argon2Params,
    ) -> PaserkResult<PaserkSecret<V>> {
        use crate::core::operations::pbkw::pbkw_unwrap_secret_k2k4;

        if self.ciphertext.len() != 64 {
            return Err(PaserkError::InvalidKey);
        }

        let mut ciphertext = [0u8; 64];
        ciphertext.copy_from_slice(&self.ciphertext);

        let header = Self::header();
        let plaintext = pbkw_unwrap_secret_k2k4(
            &self.salt,
            &self.nonce,
            &ciphertext,
            &self.tag,
            password,
            &params,
            &header,
        )?;

        Ok(PaserkSecret::from(plaintext))
    }
}

// =============================================================================
// Display (serialization to PASERK string)
// =============================================================================

impl<V: PaserkVersion> Display for PaserkSecretPw<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Concatenate salt || nonce || ciphertext || tag
        let mut data =
            Vec::with_capacity(ARGON2_SALT_SIZE + XCHACHA20_NONCE_SIZE + self.ciphertext.len() + PBKW_TAG_SIZE);
        data.extend_from_slice(&self.salt);
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

impl<V: PaserkVersion> Debug for PaserkSecretPw<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaserkSecretPw")
            .field("version", &V::PREFIX)
            .field("salt", &"[...]")
            .field("nonce", &"[...]")
            .field("ciphertext", &"[ENCRYPTED]")
            .field("tag", &"[...]")
            .finish()
    }
}

// =============================================================================
// TryFrom (parsing from PASERK string)
// =============================================================================

impl<V: PaserkVersion> TryFrom<&str> for PaserkSecretPw<V> {
    type Error = PaserkError;

    fn try_from(paserk: &str) -> Result<Self, Self::Error> {
        let expected_header = Self::header();

        if !paserk.starts_with(&expected_header) {
            let parts: Vec<&str> = paserk.splitn(3, '.').collect();
            if parts.len() < 3 {
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

        let expected_key_size = Self::expected_key_size();
        let expected_len = ARGON2_SALT_SIZE + XCHACHA20_NONCE_SIZE + expected_key_size + PBKW_TAG_SIZE;
        if data.len() != expected_len {
            return Err(PaserkError::InvalidKey);
        }

        let mut salt = [0u8; ARGON2_SALT_SIZE];
        let mut nonce = [0u8; XCHACHA20_NONCE_SIZE];
        let mut tag = [0u8; PBKW_TAG_SIZE];

        let mut offset = 0;
        salt.copy_from_slice(&data[offset..offset + ARGON2_SALT_SIZE]);
        offset += ARGON2_SALT_SIZE;
        nonce.copy_from_slice(&data[offset..offset + XCHACHA20_NONCE_SIZE]);
        offset += XCHACHA20_NONCE_SIZE;
        let ciphertext = data[offset..offset + expected_key_size].to_vec();
        offset += expected_key_size;
        tag.copy_from_slice(&data[offset..]);

        Ok(Self {
            salt,
            nonce,
            ciphertext,
            tag,
            _version: PhantomData,
        })
    }
}

impl<V: PaserkVersion> TryFrom<String> for PaserkSecretPw<V> {
    type Error = PaserkError;

    fn try_from(paserk: String) -> Result<Self, Self::Error> {
        Self::try_from(paserk.as_str())
    }
}

// =============================================================================
// PartialEq
// =============================================================================

impl<V: PaserkVersion> PartialEq for PaserkSecretPw<V> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        if self.ciphertext.len() != other.ciphertext.len() {
            return false;
        }
        self.salt.ct_eq(&other.salt).into()
            && self.nonce.ct_eq(&other.nonce).into()
            && self.ciphertext.ct_eq(&other.ciphertext).into()
            && self.tag.ct_eq(&other.tag).into()
    }
}

impl<V: PaserkVersion> Eq for PaserkSecretPw<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    #[cfg(any(feature = "k2", feature = "k4"))]
    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 1024, // 1 MiB for fast tests
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_header() {
        assert_eq!(PaserkSecretPw::<K4>::header(), "k4.secret-pw.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_wrap_unwrap_roundtrip() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_params())?;

        let unwrapped = wrapped.try_unwrap(password, test_params())?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_serialize_parse_roundtrip() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_params())?;

        let serialized = wrapped.to_string();
        assert!(serialized.starts_with("k4.secret-pw."));

        let parsed = PaserkSecretPw::<K4>::try_from(serialized.as_str())?;

        assert_eq!(wrapped, parsed);

        let unwrapped = parsed.try_unwrap(password, test_params())?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unwrap_wrong_password() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_params())?;

        let result = wrapped.try_unwrap(wrong_password, test_params());
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn test_parse_invalid_version() {
        let result = PaserkSecretPw::<K4>::try_from("k2.secret-pw.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_parse_invalid_type() {
        let result = PaserkSecretPw::<K4>::try_from("k4.local-pw.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_parse_invalid_data_length() {
        let result = PaserkSecretPw::<K4>::try_from("k4.secret-pw.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidKey)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_params())?;

        let debug_str = format!("{wrapped:?}");
        assert!(debug_str.contains("PaserkSecretPw"));
        assert!(debug_str.contains("k4"));
        assert!(debug_str.contains("[ENCRYPTED]"));
        Ok(())
    }
}
