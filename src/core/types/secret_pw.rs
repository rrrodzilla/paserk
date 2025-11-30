//! `PaserkSecretPw` - Secret key wrapped with a password.
//!
//! This module provides the `PaserkSecretPw` type for storing secret (signing) keys
//! that have been encrypted with a password using PBKW.
//!
//! Format for K2/K4: `k{version}.secret-pw.{base64url(salt || memlimit_BE64 || opslimit_BE32 || parallelism_BE32 || nonce || ciphertext || tag)}`
//! Format for K1/K3: `k{version}.secret-pw.{base64url(salt || iterations_BE32 || nonce || ciphertext || tag)}`

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use base64::prelude::*;

use crate::core::error::{PaserkError, PaserkResult};
use crate::core::version::PaserkVersion;

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::operations::pbkw::{
    Argon2Params, ARGON2_SALT_SIZE, PBKW_TAG_SIZE, XCHACHA20_NONCE_SIZE,
};

#[cfg(any(feature = "k1-insecure", feature = "k3"))]
use crate::core::operations::pbkw::{
    AES_CTR_NONCE_SIZE, PBKDF2_SALT_SIZE, PBKW_K1K3_TAG_SIZE, Pbkdf2Params,
};

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
/// - Uses Argon2id (K2/K4) or PBKDF2-SHA384 (K1/K3) for password stretching
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
    /// The raw serialized data including embedded params.
    /// Size varies by version:
    /// - K2/K4: salt(16) + memlimit(8) + opslimit(4) + parallelism(4) + nonce(24) + ciphertext(64) + tag(32) = 152 bytes
    /// - K3: salt(32) + iterations(4) + nonce(16) + ciphertext(48) + tag(48) = 148 bytes
    data: Vec<u8>,

    /// Version marker.
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> PaserkSecretPw<V> {
    /// The PASERK type identifier.
    pub const TYPE: &'static str = "secret-pw";

    /// Returns the header for this PASERK type (e.g., "k4.secret-pw.").
    #[must_use]
    pub fn header() -> String {
        format!("{}.{}.", V::PREFIX, Self::TYPE)
    }

    /// Creates a new `PaserkSecretPw` from raw data bytes.
    const fn from_data(data: Vec<u8>) -> Self {
        Self {
            data,
            _version: PhantomData,
        }
    }

    /// Returns a reference to the raw data bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns a reference to the ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        // Ciphertext is positioned after salt + params + nonce
        let (salt_size, params_size, nonce_size) = Self::sizes_for_version();
        let key_size = Self::expected_key_size();
        let offset = salt_size + params_size + nonce_size;
        &self.data[offset..offset + key_size]
    }

    /// Returns the expected data size for this version.
    #[must_use]
    const fn data_size() -> usize {
        let key_size = Self::expected_key_size();
        match V::VERSION {
            // K2/K4: salt(16) + memlimit(8) + opslimit(4) + parallelism(4) + nonce(24) + ciphertext(64) + tag(32) = 152
            2 | 4 => 16 + 8 + 4 + 4 + 24 + key_size + 32,
            // K3: salt(32) + iterations(4) + nonce(16) + ciphertext(48) + tag(48) = 148
            3 => 32 + 4 + 16 + key_size + 48,
            // K1: Not supported
            _ => 0,
        }
    }

    /// Returns (`salt_size`, `params_size`, `nonce_size`) based on version.
    #[must_use]
    const fn sizes_for_version() -> (usize, usize, usize) {
        match V::VERSION {
            // K1/K3: salt(32) + iterations(4) + nonce(16)
            1 | 3 => (32, 4, 16),
            // K2/K4: salt(16) + memlimit(8)+opslimit(4)+parallelism(4)=16 + nonce(24)
            _ => (16, 16, 24),
        }
    }

    /// Returns the expected secret key size for this version.
    #[must_use]
    const fn expected_key_size() -> usize {
        match V::VERSION {
            2 | 4 => 64, // Ed25519 secret key
            3 => 48,     // P-384 secret key
            _ => 0,      // RSA (variable, not supported yet)
        }
    }
}

// =============================================================================
// PBKW wrapping for K2/K4 (Argon2id + XChaCha20 + BLAKE2b)
// =============================================================================

#[cfg(any(feature = "k2", feature = "k4"))]
impl<V: PaserkVersion + crate::core::version::UsesArgon2> PaserkSecretPw<V> {
    /// Wraps a secret key with a password using PBKW (K2/K4: Argon2id).
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

        // Concatenate: salt || memlimit_BE64 || opslimit_BE32 || parallelism_BE32 || nonce || ciphertext || tag
        let memlimit_bytes = u64::from(params.memory_kib) * 1024;
        let mut data = Vec::with_capacity(ARGON2_SALT_SIZE + 8 + 4 + 4 + XCHACHA20_NONCE_SIZE + 64 + PBKW_TAG_SIZE);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&memlimit_bytes.to_be_bytes());
        data.extend_from_slice(&params.iterations.to_be_bytes());
        data.extend_from_slice(&params.parallelism.to_be_bytes());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        data.extend_from_slice(&tag);

        Ok(Self::from_data(data))
    }

    /// Unwraps the encrypted key using the password (K2/K4: Argon2id).
    ///
    /// # Arguments
    ///
    /// * `password` - The password used for wrapping
    /// * `_params` - Ignored; the Argon2id parameters are extracted from the serialized data
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
        _params: Argon2Params,
    ) -> PaserkResult<PaserkSecret<V>> {
        use crate::core::operations::pbkw::pbkw_unwrap_secret_k2k4;

        let header = Self::header();

        // Parse components from data: salt || memlimit_BE64 || opslimit_BE32 || parallelism_BE32 || nonce || ciphertext || tag
        let mut salt = [0u8; ARGON2_SALT_SIZE];
        let mut nonce = [0u8; XCHACHA20_NONCE_SIZE];
        let mut ciphertext = [0u8; 64];
        let mut tag = [0u8; PBKW_TAG_SIZE];

        let mut offset = 0;
        salt.copy_from_slice(&self.data[offset..offset + ARGON2_SALT_SIZE]);
        offset += ARGON2_SALT_SIZE;

        // Extract embedded Argon2 parameters
        let memlimit_bytes = u64::from_be_bytes(self.data[offset..offset + 8].try_into().map_err(|_| PaserkError::InvalidKey)?);
        offset += 8;
        let opslimit = u32::from_be_bytes(self.data[offset..offset + 4].try_into().map_err(|_| PaserkError::InvalidKey)?);
        offset += 4;
        let parallelism = u32::from_be_bytes(self.data[offset..offset + 4].try_into().map_err(|_| PaserkError::InvalidKey)?);
        offset += 4;

        // Convert memlimit from bytes to KiB
        let memory_kib = u32::try_from(memlimit_bytes / 1024).map_err(|_| PaserkError::InvalidKey)?;
        let params = Argon2Params {
            memory_kib,
            iterations: opslimit,
            parallelism,
        };

        nonce.copy_from_slice(&self.data[offset..offset + XCHACHA20_NONCE_SIZE]);
        offset += XCHACHA20_NONCE_SIZE;
        ciphertext.copy_from_slice(&self.data[offset..offset + 64]);
        offset += 64;
        tag.copy_from_slice(&self.data[offset..]);

        let plaintext = pbkw_unwrap_secret_k2k4(
            &salt,
            &nonce,
            &ciphertext,
            &tag,
            password,
            &params,
            &header,
        )?;

        Ok(PaserkSecret::from(plaintext))
    }
}

// =============================================================================
// PBKW wrapping for K3 (PBKDF2-SHA384 + AES-256-CTR + HMAC-SHA384)
// =============================================================================

#[cfg(feature = "k3")]
impl PaserkSecretPw<crate::core::version::K3> {
    /// Wraps a P-384 secret key with a password using PBKW (K3: PBKDF2).
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to wrap
    /// * `password` - The password to use for wrapping
    /// * `params` - PBKDF2 parameters
    ///
    /// # Returns
    ///
    /// A new `PaserkSecretPw` containing the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic operation fails.
    pub fn try_wrap_pbkdf2(
        key: &PaserkSecret<crate::core::version::K3>,
        password: &[u8],
        params: Pbkdf2Params,
    ) -> PaserkResult<Self> {
        use crate::core::operations::pbkw::pbkw_wrap_secret_k3;

        let key_bytes = key.as_bytes();
        if key_bytes.len() != 48 {
            return Err(PaserkError::InvalidKey);
        }

        let mut plaintext = [0u8; 48];
        plaintext.copy_from_slice(key_bytes);

        let header = Self::header();
        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_secret_k3(&plaintext, password, params, &header)?;

        // Concatenate: salt || iterations_BE32 || nonce || ciphertext || tag
        let mut data = Vec::with_capacity(PBKDF2_SALT_SIZE + 4 + AES_CTR_NONCE_SIZE + 48 + PBKW_K1K3_TAG_SIZE);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&params.iterations.to_be_bytes());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        data.extend_from_slice(&tag);

        Ok(Self::from_data(data))
    }

    /// Unwraps the encrypted key using the password (K3: PBKDF2).
    ///
    /// # Arguments
    ///
    /// * `password` - The password used for wrapping
    /// * `_params` - Ignored; the PBKDF2 parameters are extracted from the serialized data
    ///
    /// # Returns
    ///
    /// The original unwrapped secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the password is wrong.
    pub fn try_unwrap_pbkdf2(
        &self,
        password: &[u8],
        _params: Pbkdf2Params,
    ) -> PaserkResult<PaserkSecret<crate::core::version::K3>> {
        use crate::core::operations::pbkw::pbkw_unwrap_secret_k3;

        let header = Self::header();

        // Parse components from data: salt || iterations_BE32 || nonce || ciphertext || tag
        let mut salt = [0u8; PBKDF2_SALT_SIZE];
        let mut nonce = [0u8; AES_CTR_NONCE_SIZE];
        let mut ciphertext = [0u8; 48];
        let mut tag = [0u8; PBKW_K1K3_TAG_SIZE];

        let mut offset = 0;
        salt.copy_from_slice(&self.data[offset..offset + PBKDF2_SALT_SIZE]);
        offset += PBKDF2_SALT_SIZE;

        // Extract embedded PBKDF2 iterations
        let iterations = u32::from_be_bytes(self.data[offset..offset + 4].try_into().map_err(|_| PaserkError::InvalidKey)?);
        offset += 4;
        let params = Pbkdf2Params { iterations };

        nonce.copy_from_slice(&self.data[offset..offset + AES_CTR_NONCE_SIZE]);
        offset += AES_CTR_NONCE_SIZE;
        ciphertext.copy_from_slice(&self.data[offset..offset + 48]);
        offset += 48;
        tag.copy_from_slice(&self.data[offset..]);

        let plaintext = pbkw_unwrap_secret_k3(
            &salt,
            &nonce,
            &ciphertext,
            &tag,
            password,
            params,
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
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(&self.data);
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
            .field("data_len", &self.data.len())
            .field("ciphertext", &"[ENCRYPTED]")
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

        if data.len() != Self::data_size() {
            return Err(PaserkError::InvalidKey);
        }

        Ok(Self::from_data(data))
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
        self.data.ct_eq(&other.data).into()
    }
}

impl<V: PaserkVersion> Eq for PaserkSecretPw<V> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "k4")]
    use crate::core::version::K4;

    #[cfg(feature = "k3")]
    use crate::core::version::K3;

    #[cfg(any(feature = "k2", feature = "k4"))]
    fn test_argon2_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 1024, // 1 MiB for fast tests
            iterations: 1,
            parallelism: 1,
        }
    }

    #[cfg(feature = "k3")]
    fn test_pbkdf2_params() -> Pbkdf2Params {
        Pbkdf2Params { iterations: 1000 }
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_header() {
        assert_eq!(PaserkSecretPw::<K4>::header(), "k4.secret-pw.");
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_header_k3() {
        assert_eq!(PaserkSecretPw::<K3>::header(), "k3.secret-pw.");
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_wrap_unwrap_roundtrip() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_argon2_params())?;

        let unwrapped = wrapped.try_unwrap(password, test_argon2_params())?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_wrap_unwrap_roundtrip_k3() -> PaserkResult<()> {
        let key = PaserkSecret::<K3>::from([0x42u8; 48]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K3>::try_wrap_pbkdf2(&key, password, test_pbkdf2_params())?;

        let unwrapped = wrapped.try_unwrap_pbkdf2(password, test_pbkdf2_params())?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_serialize_parse_roundtrip() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_argon2_params())?;

        let serialized = wrapped.to_string();
        assert!(serialized.starts_with("k4.secret-pw."));

        let parsed = PaserkSecretPw::<K4>::try_from(serialized.as_str())?;

        assert_eq!(wrapped, parsed);

        let unwrapped = parsed.try_unwrap(password, test_argon2_params())?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_serialize_parse_roundtrip_k3() -> PaserkResult<()> {
        let key = PaserkSecret::<K3>::from([0x42u8; 48]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K3>::try_wrap_pbkdf2(&key, password, test_pbkdf2_params())?;

        let serialized = wrapped.to_string();
        assert!(serialized.starts_with("k3.secret-pw."));

        let parsed = PaserkSecretPw::<K3>::try_from(serialized.as_str())?;

        assert_eq!(wrapped, parsed);

        let unwrapped = parsed.try_unwrap_pbkdf2(password, test_pbkdf2_params())?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unwrap_wrong_password() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_argon2_params())?;

        let result = wrapped.try_unwrap(wrong_password, test_argon2_params());
        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_parse_invalid_version() {
        let result = PaserkSecretPw::<K4>::try_from("k2.secret-pw.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_parse_invalid_type() {
        let result = PaserkSecretPw::<K4>::try_from("k4.local-pw.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_parse_invalid_data_length() {
        let result = PaserkSecretPw::<K4>::try_from("k4.secret-pw.AAAA");
        assert!(matches!(result, Err(PaserkError::InvalidKey)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_debug() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        let wrapped = PaserkSecretPw::<K4>::try_wrap(&key, password, test_argon2_params())?;

        let debug_str = format!("{wrapped:?}");
        assert!(debug_str.contains("PaserkSecretPw"));
        assert!(debug_str.contains("k4"));
        assert!(debug_str.contains("[ENCRYPTED]"));
        Ok(())
    }
}
