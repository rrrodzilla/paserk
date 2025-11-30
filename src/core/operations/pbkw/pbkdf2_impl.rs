//! PBKDF2-based PBKW implementation for K1/K3.
//!
//! This module implements password-based key wrapping using PBKDF2-SHA384 for
//! key derivation and AES-256-CTR + HMAC-SHA384 for authenticated encryption.

use crate::core::error::{PaserkError, PaserkResult};

/// Salt size for PBKDF2 (32 bytes).
pub const PBKDF2_SALT_SIZE: usize = 32;

/// Nonce size for AES-256-CTR (16 bytes).
pub const AES_CTR_NONCE_SIZE: usize = 16;

/// Tag size for HMAC-SHA384 (48 bytes).
pub const PBKW_K1K3_TAG_SIZE: usize = 48;

/// Output type for local (32-byte) key wrapping: (salt, nonce, ciphertext, tag).
pub(crate) type PbkwLocalOutputK1K3 = (
    [u8; PBKDF2_SALT_SIZE],
    [u8; AES_CTR_NONCE_SIZE],
    [u8; 32],
    [u8; PBKW_K1K3_TAG_SIZE],
);

/// Output type for secret key wrapping: (salt, nonce, ciphertext, tag).
/// K1 uses RSA keys (variable size), K3 uses P-384 keys (48 bytes).
pub(crate) type PbkwSecretOutputK3 = (
    [u8; PBKDF2_SALT_SIZE],
    [u8; AES_CTR_NONCE_SIZE],
    [u8; 48],
    [u8; PBKW_K1K3_TAG_SIZE],
);

/// Domain separation for PBKW encryption key derivation.
const PBKW_EK_DOMAIN: &[u8] = b"paserk-wrap.pie-local";

/// Domain separation for PBKW authentication key derivation.
const PBKW_AK_SUFFIX: &[u8] = b"auth-key-for-tag";

/// Default PBKDF2 parameters.
#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2Params {
    /// Number of iterations.
    pub iterations: u32,
}

impl Default for Pbkdf2Params {
    fn default() -> Self {
        Self::moderate()
    }
}

impl Pbkdf2Params {
    /// Interactive profile: Fast, suitable for interactive logins.
    /// - Iterations: 100,000
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            iterations: 100_000,
        }
    }

    /// Moderate profile: Balanced security and performance.
    /// - Iterations: 310,000 (OWASP 2023 recommendation for SHA-384)
    #[must_use]
    pub const fn moderate() -> Self {
        Self {
            iterations: 310_000,
        }
    }

    /// Sensitive profile: High security, slower computation.
    /// - Iterations: 600,000
    #[must_use]
    pub const fn sensitive() -> Self {
        Self {
            iterations: 600_000,
        }
    }
}

/// Derives encryption and authentication keys using PBKDF2-SHA384 and HMAC-SHA384.
#[cfg(any(feature = "k1", feature = "k3"))]
fn derive_keys_k1k3(
    password: &[u8],
    salt: &[u8; PBKDF2_SALT_SIZE],
    iterations: u32,
    domain: &[u8],
) -> PaserkResult<([u8; 32], [u8; 48])> {
    use hmac::{Hmac, Mac};
    use sha2::Sha384;

    // Derive pre-shared key using PBKDF2-SHA384
    // Output is 32 bytes (256 bits) for the PSK
    let mut psk = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha384>>(password, salt, iterations, &mut psk)
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    // Derive encryption key: Ek = HMAC-SHA384(psk, domain), truncated to 32 bytes
    let mut ek_mac =
        <Hmac<Sha384> as Mac>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    ek_mac.update(domain);
    let ek_result = ek_mac.finalize().into_bytes();
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&ek_result[..32]);

    // Derive authentication key: Ak = HMAC-SHA384(psk, domain || auth-key-for-tag)
    let mut ak_mac =
        <Hmac<Sha384> as Mac>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    ak_mac.update(domain);
    ak_mac.update(PBKW_AK_SUFFIX);
    let auth_key: [u8; 48] = ak_mac.finalize().into_bytes().into();

    Ok((encryption_key, auth_key))
}

/// Encrypts data using AES-256-CTR.
#[cfg(any(feature = "k1", feature = "k3"))]
fn aes_ctr_encrypt(key: &[u8; 32], nonce: &[u8; AES_CTR_NONCE_SIZE], data: &mut [u8]) {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;

    type Aes256Ctr = Ctr128BE<aes::Aes256>;
    let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
}

/// Computes HMAC-SHA384 tag.
#[cfg(any(feature = "k1", feature = "k3"))]
fn compute_tag_k1k3(
    auth_key: &[u8; 48],
    header: &str,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> PaserkResult<[u8; PBKW_K1K3_TAG_SIZE]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha384;

    let mut tag_mac =
        <Hmac<Sha384> as Mac>::new_from_slice(auth_key).map_err(|_| PaserkError::CryptoError)?;
    tag_mac.update(header.as_bytes());
    tag_mac.update(salt);
    tag_mac.update(nonce);
    tag_mac.update(ciphertext);
    Ok(tag_mac.finalize().into_bytes().into())
}

/// Wraps a local (symmetric) key using PBKW for K1/K3.
///
/// # Arguments
///
/// * `plaintext_key` - The 32-byte key to wrap
/// * `password` - The password to use for wrapping
/// * `params` - PBKDF2 parameters
/// * `header` - The PASERK header (e.g., "k3.local-pw.")
///
/// # Returns
///
/// A tuple of (salt, nonce, ciphertext, tag).
#[cfg(any(feature = "k1", feature = "k3"))]
pub fn pbkw_wrap_local_k1k3(
    plaintext_key: &[u8; 32],
    password: &[u8],
    params: &Pbkdf2Params,
    header: &str,
) -> PaserkResult<PbkwLocalOutputK1K3> {
    use rand_core::{OsRng, TryRngCore};

    // Generate random salt and nonce
    let mut salt = [0u8; PBKDF2_SALT_SIZE];
    let mut nonce = [0u8; AES_CTR_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| PaserkError::CryptoError)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive keys
    let (encryption_key, auth_key) =
        derive_keys_k1k3(password, &salt, params.iterations, PBKW_EK_DOMAIN)?;

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    aes_ctr_encrypt(&encryption_key, &nonce, &mut ciphertext);

    // Compute authentication tag
    let tag = compute_tag_k1k3(&auth_key, header, &salt, &nonce, &ciphertext)?;

    Ok((salt, nonce, ciphertext, tag))
}

/// Unwraps a local (symmetric) key using PBKW for K1/K3.
///
/// # Arguments
///
/// * `salt` - The 32-byte PBKDF2 salt
/// * `nonce` - The 16-byte AES-CTR nonce
/// * `ciphertext` - The 32-byte encrypted key
/// * `tag` - The 48-byte authentication tag
/// * `password` - The password used for wrapping
/// * `params` - PBKDF2 parameters (must match those used for wrapping)
/// * `header` - The PASERK header (e.g., "k3.local-pw.")
///
/// # Returns
///
/// The unwrapped 32-byte plaintext key.
#[cfg(any(feature = "k1", feature = "k3"))]
pub fn pbkw_unwrap_local_k1k3(
    salt: &[u8; PBKDF2_SALT_SIZE],
    nonce: &[u8; AES_CTR_NONCE_SIZE],
    ciphertext: &[u8; 32],
    tag: &[u8; PBKW_K1K3_TAG_SIZE],
    password: &[u8],
    params: &Pbkdf2Params,
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use subtle::ConstantTimeEq;

    // Derive keys
    let (encryption_key, auth_key) =
        derive_keys_k1k3(password, salt, params.iterations, PBKW_EK_DOMAIN)?;

    // Verify authentication tag
    let computed_tag = compute_tag_k1k3(&auth_key, header, salt, nonce, ciphertext)?;

    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        aes_ctr_encrypt(&encryption_key, nonce, &mut plaintext);
        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

/// Wraps a P-384 secret key using PBKW for K3.
#[cfg(feature = "k3")]
pub fn pbkw_wrap_secret_k3(
    plaintext_key: &[u8; 48],
    password: &[u8],
    params: &Pbkdf2Params,
    header: &str,
) -> PaserkResult<PbkwSecretOutputK3> {
    use rand_core::{OsRng, TryRngCore};

    const PBKW_SECRET_DOMAIN: &[u8] = b"paserk-wrap.pie-secret";

    // Generate random salt and nonce
    let mut salt = [0u8; PBKDF2_SALT_SIZE];
    let mut nonce = [0u8; AES_CTR_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| PaserkError::CryptoError)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive keys
    let (encryption_key, auth_key) =
        derive_keys_k1k3(password, &salt, params.iterations, PBKW_SECRET_DOMAIN)?;

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    aes_ctr_encrypt(&encryption_key, &nonce, &mut ciphertext);

    // Compute authentication tag
    let tag = compute_tag_k1k3(&auth_key, header, &salt, &nonce, &ciphertext)?;

    Ok((salt, nonce, ciphertext, tag))
}

/// Unwraps a P-384 secret key using PBKW for K3.
#[cfg(feature = "k3")]
pub fn pbkw_unwrap_secret_k3(
    salt: &[u8; PBKDF2_SALT_SIZE],
    nonce: &[u8; AES_CTR_NONCE_SIZE],
    ciphertext: &[u8; 48],
    tag: &[u8; PBKW_K1K3_TAG_SIZE],
    password: &[u8],
    params: &Pbkdf2Params,
    header: &str,
) -> PaserkResult<[u8; 48]> {
    use subtle::ConstantTimeEq;

    const PBKW_SECRET_DOMAIN: &[u8] = b"paserk-wrap.pie-secret";

    // Derive keys
    let (encryption_key, auth_key) =
        derive_keys_k1k3(password, salt, params.iterations, PBKW_SECRET_DOMAIN)?;

    // Verify authentication tag
    let computed_tag = compute_tag_k1k3(&auth_key, header, salt, nonce, ciphertext)?;

    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        aes_ctr_encrypt(&encryption_key, nonce, &mut plaintext);
        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use minimal params for fast tests
    fn test_params() -> Pbkdf2Params {
        Pbkdf2Params { iterations: 1000 }
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pbkw_wrap_unwrap_local_k3_roundtrip() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let params = test_params();
        let header = "k3.local-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_local_k1k3(&plaintext_key, password, &params, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pbkw_unwrap_local_k1k3(&salt, &nonce, &ciphertext, &tag, password, &params, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1")]
    fn test_pbkw_wrap_unwrap_local_k1_roundtrip() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let params = test_params();
        let header = "k1.local-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_local_k1k3(&plaintext_key, password, &params, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pbkw_unwrap_local_k1k3(&salt, &nonce, &ciphertext, &tag, password, &params, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pbkw_wrap_unwrap_secret_k3_roundtrip() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 48];
        let password = b"hunter2";
        let params = test_params();
        let header = "k3.secret-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_secret_k3(&plaintext_key, password, &params, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pbkw_unwrap_secret_k3(&salt, &nonce, &ciphertext, &tag, password, &params, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pbkw_unwrap_wrong_password() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let wrong_password = b"hunter3";
        let params = test_params();
        let header = "k3.local-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_local_k1k3(&plaintext_key, password, &params, header)?;

        let result = pbkw_unwrap_local_k1k3(
            &salt,
            &nonce,
            &ciphertext,
            &tag,
            wrong_password,
            &params,
            header,
        );

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pbkw_unwrap_modified_tag() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let params = test_params();
        let header = "k3.local-pw.";

        let (salt, nonce, ciphertext, mut tag) =
            pbkw_wrap_local_k1k3(&plaintext_key, password, &params, header)?;

        tag[0] ^= 0xff;

        let result =
            pbkw_unwrap_local_k1k3(&salt, &nonce, &ciphertext, &tag, password, &params, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn test_pbkdf2_params_presets() {
        let interactive = Pbkdf2Params::interactive();
        assert_eq!(interactive.iterations, 100_000);

        let moderate = Pbkdf2Params::moderate();
        assert_eq!(moderate.iterations, 310_000);

        let sensitive = Pbkdf2Params::sensitive();
        assert_eq!(sensitive.iterations, 600_000);
    }
}
