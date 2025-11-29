//! Argon2id-based PBKW implementation for K2/K4.
//!
//! This module implements password-based key wrapping using Argon2id for
//! key derivation and XChaCha20 + BLAKE2b for authenticated encryption.

use crate::core::error::{PaserkError, PaserkResult};

/// Salt size for Argon2id (16 bytes).
pub const ARGON2_SALT_SIZE: usize = 16;

/// Nonce size for XChaCha20 (24 bytes).
pub const XCHACHA20_NONCE_SIZE: usize = 24;

/// Tag size for BLAKE2b-MAC (32 bytes).
pub const PBKW_TAG_SIZE: usize = 32;

/// Output type for local (32-byte) key wrapping: (salt, nonce, ciphertext, tag).
pub(crate) type PbkwLocalOutput = (
    [u8; ARGON2_SALT_SIZE],
    [u8; XCHACHA20_NONCE_SIZE],
    [u8; 32],
    [u8; PBKW_TAG_SIZE],
);

/// Output type for secret (64-byte) key wrapping: (salt, nonce, ciphertext, tag).
pub(crate) type PbkwSecretOutput = (
    [u8; ARGON2_SALT_SIZE],
    [u8; XCHACHA20_NONCE_SIZE],
    [u8; 64],
    [u8; PBKW_TAG_SIZE],
);

/// Domain separation for PBKW encryption key derivation.
const PBKW_EK_DOMAIN: &[u8] = b"paserk-wrap.pie-local";

/// Domain separation for PBKW authentication key derivation.
const PBKW_AK_SUFFIX: &[u8] = b"auth-key-for-tag";

/// Default Argon2id parameters.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of iterations.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::moderate()
    }
}

impl Argon2Params {
    /// Interactive profile: Fast, suitable for interactive logins.
    /// - Memory: 64 MiB
    /// - Iterations: 2
    /// - Parallelism: 1
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    /// Moderate profile: Balanced security and performance.
    /// - Memory: 256 MiB
    /// - Iterations: 3
    /// - Parallelism: 1
    #[must_use]
    pub const fn moderate() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    /// Sensitive profile: High security, slower computation.
    /// - Memory: 1 GiB
    /// - Iterations: 4
    /// - Parallelism: 1
    #[must_use]
    pub const fn sensitive() -> Self {
        Self {
            memory_kib: 1024 * 1024,
            iterations: 4,
            parallelism: 1,
        }
    }
}

/// Wraps a local (symmetric) key using PBKW for K2/K4.
///
/// # Arguments
///
/// * `plaintext_key` - The 32-byte key to wrap
/// * `password` - The password to use for wrapping
/// * `params` - Argon2id parameters
/// * `header` - The PASERK header (e.g., "k4.local-pw.")
///
/// # Returns
///
/// A tuple of (salt, nonce, ciphertext, tag).
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pbkw_wrap_local_k2k4(
    plaintext_key: &[u8; 32],
    password: &[u8],
    params: &Argon2Params,
    header: &str,
) -> PaserkResult<PbkwLocalOutput> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use rand_core::{OsRng, TryRngCore};

    // Generate random salt and nonce
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    let mut nonce = [0u8; XCHACHA20_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| PaserkError::CryptoError)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Build Argon2id parameters
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .build()
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Derive pre-shared key
    let mut psk = [0u8; 32];
    argon2
        .hash_password_into(password, &salt, &mut psk)
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    // Derive encryption key: Ek = BLAKE2b-MAC(psk, "paserk-wrap.pie-local", 32)
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut ek_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ek_mac, PBKW_EK_DOMAIN);
    let encryption_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ek_mac).into();

    // Derive authentication key: Ak = BLAKE2b-MAC(psk, "paserk-wrap.pie-local" || "auth-key-for-tag", 32)
    let mut ak_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_EK_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_AK_SUFFIX);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ak_mac).into();

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag: tag = BLAKE2b-MAC(Ak, header || salt || nonce || ciphertext, 32)
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &salt);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; PBKW_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    Ok((salt, nonce, ciphertext, tag))
}

/// Unwraps a local (symmetric) key using PBKW for K2/K4.
///
/// # Arguments
///
/// * `salt` - The 16-byte Argon2 salt
/// * `nonce` - The 24-byte XChaCha20 nonce
/// * `ciphertext` - The 32-byte encrypted key
/// * `tag` - The 32-byte authentication tag
/// * `password` - The password used for wrapping
/// * `params` - Argon2id parameters (must match those used for wrapping)
/// * `header` - The PASERK header (e.g., "k4.local-pw.")
///
/// # Returns
///
/// The unwrapped 32-byte plaintext key.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pbkw_unwrap_local_k2k4(
    salt: &[u8; ARGON2_SALT_SIZE],
    nonce: &[u8; XCHACHA20_NONCE_SIZE],
    ciphertext: &[u8; 32],
    tag: &[u8; PBKW_TAG_SIZE],
    password: &[u8],
    params: &Argon2Params,
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use subtle::ConstantTimeEq;

    // Build Argon2id parameters
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .build()
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Derive pre-shared key
    let mut psk = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut psk)
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    // Derive encryption key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut ek_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ek_mac, PBKW_EK_DOMAIN);
    let encryption_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ek_mac).into();

    // Derive authentication key
    let mut ak_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_EK_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_AK_SUFFIX);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ak_mac).into();

    // Verify authentication tag
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, salt);
    <Blake2bMac32 as Update>::update(&mut tag_mac, nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, ciphertext);
    let computed_tag: [u8; PBKW_TAG_SIZE] =
        <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        let mut cipher = XChaCha20::new(&encryption_key.into(), nonce.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

/// Wraps a secret (signing) key using PBKW for K2/K4.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pbkw_wrap_secret_k2k4(
    plaintext_key: &[u8; 64],
    password: &[u8],
    params: &Argon2Params,
    header: &str,
) -> PaserkResult<PbkwSecretOutput> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use rand_core::{OsRng, TryRngCore};

    // Generate random salt and nonce
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    let mut nonce = [0u8; XCHACHA20_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| PaserkError::CryptoError)?;
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Build Argon2id parameters
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .build()
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Derive pre-shared key
    let mut psk = [0u8; 32];
    argon2
        .hash_password_into(password, &salt, &mut psk)
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    // Use "paserk-wrap.pie-secret" for secret key wrapping
    const PBKW_SECRET_DOMAIN: &[u8] = b"paserk-wrap.pie-secret";

    // Derive encryption key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut ek_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ek_mac, PBKW_SECRET_DOMAIN);
    let encryption_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ek_mac).into();

    // Derive authentication key
    let mut ak_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_SECRET_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_AK_SUFFIX);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ak_mac).into();

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &salt);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; PBKW_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    Ok((salt, nonce, ciphertext, tag))
}

/// Unwraps a secret (signing) key using PBKW for K2/K4.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pbkw_unwrap_secret_k2k4(
    salt: &[u8; ARGON2_SALT_SIZE],
    nonce: &[u8; XCHACHA20_NONCE_SIZE],
    ciphertext: &[u8; 64],
    tag: &[u8; PBKW_TAG_SIZE],
    password: &[u8],
    params: &Argon2Params,
    header: &str,
) -> PaserkResult<[u8; 64]> {
    use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use subtle::ConstantTimeEq;

    // Build Argon2id parameters
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .build()
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Derive pre-shared key
    let mut psk = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut psk)
        .map_err(|_| PaserkError::KeyDerivationFailed)?;

    const PBKW_SECRET_DOMAIN: &[u8] = b"paserk-wrap.pie-secret";

    // Derive encryption key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut ek_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ek_mac, PBKW_SECRET_DOMAIN);
    let encryption_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ek_mac).into();

    // Derive authentication key
    let mut ak_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&psk).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_SECRET_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut ak_mac, PBKW_AK_SUFFIX);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ak_mac).into();

    // Verify authentication tag
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, salt);
    <Blake2bMac32 as Update>::update(&mut tag_mac, nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, ciphertext);
    let computed_tag: [u8; PBKW_TAG_SIZE] =
        <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        let mut cipher = XChaCha20::new(&encryption_key.into(), nonce.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use minimal params for fast tests
    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 1024, // 1 MiB
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pbkw_wrap_unwrap_local_roundtrip() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let params = test_params();
        let header = "k4.local-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_local_k2k4(&plaintext_key, password, &params, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pbkw_unwrap_local_k2k4(&salt, &nonce, &ciphertext, &tag, password, &params, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pbkw_wrap_unwrap_secret_roundtrip() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 64];
        let password = b"hunter2";
        let params = test_params();
        let header = "k4.secret-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_secret_k2k4(&plaintext_key, password, &params, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pbkw_unwrap_secret_k2k4(&salt, &nonce, &ciphertext, &tag, password, &params, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pbkw_unwrap_wrong_password() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let wrong_password = b"hunter3";
        let params = test_params();
        let header = "k4.local-pw.";

        let (salt, nonce, ciphertext, tag) =
            pbkw_wrap_local_k2k4(&plaintext_key, password, &params, header)?;

        let result = pbkw_unwrap_local_k2k4(
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
    #[cfg(feature = "k4")]
    fn test_pbkw_unwrap_modified_tag() -> PaserkResult<()> {
        let plaintext_key = [0x13u8; 32];
        let password = b"hunter2";
        let params = test_params();
        let header = "k4.local-pw.";

        let (salt, nonce, ciphertext, mut tag) =
            pbkw_wrap_local_k2k4(&plaintext_key, password, &params, header)?;

        tag[0] ^= 0xff;

        let result =
            pbkw_unwrap_local_k2k4(&salt, &nonce, &ciphertext, &tag, password, &params, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    fn test_argon2_params_presets() {
        let interactive = Argon2Params::interactive();
        assert_eq!(interactive.memory_kib, 64 * 1024);
        assert_eq!(interactive.iterations, 2);
        assert_eq!(interactive.parallelism, 1);

        let moderate = Argon2Params::moderate();
        assert_eq!(moderate.memory_kib, 256 * 1024);
        assert_eq!(moderate.iterations, 3);
        assert_eq!(moderate.parallelism, 1);

        let sensitive = Argon2Params::sensitive();
        assert_eq!(sensitive.memory_kib, 1024 * 1024);
        assert_eq!(sensitive.iterations, 4);
        assert_eq!(sensitive.parallelism, 1);
    }
}
