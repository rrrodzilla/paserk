//! PIE (Platform-Independent Encryption) protocol implementation.
//!
//! This module implements the PIE key wrapping protocol for PASERK.
//! - For K2/K4: Uses XChaCha20 + BLAKE2b
//! - For K1/K3: Uses AES-256-CTR + HMAC-SHA384

use crate::core::error::{PaserkError, PaserkResult};

/// Nonce size for PIE protocol (32 bytes).
pub const PIE_NONCE_SIZE: usize = 32;

/// Tag size for PIE protocol (32 bytes).
pub const PIE_TAG_SIZE: usize = 32;

/// Domain separation string for PIE KDF.
const PIE_KDF_DOMAIN: &[u8] = b"paserk-wrap.pie.";

/// Domain separation string for PIE authentication key derivation.
const PIE_AUTH_KEY_DOMAIN: &[u8] = b"auth-key-for-tag";

/// Wraps a local (symmetric) key using the PIE protocol for K2/K4.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for wrapping
/// * `plaintext_key` - The 32-byte key to wrap
/// * `header` - The PASERK header (e.g., "k4.local-wrap.pie.")
///
/// # Returns
///
/// A tuple of (nonce, ciphertext, tag) where:
/// - nonce is 32 bytes
/// - ciphertext is 32 bytes (same size as plaintext)
/// - tag is 32 bytes
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pie_wrap_local_k2k4(
    wrapping_key: &[u8; 32],
    plaintext_key: &[u8; 32],
    header: &str,
) -> PaserkResult<([u8; PIE_NONCE_SIZE], [u8; 32], [u8; PIE_TAG_SIZE])> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use rand_core::{OsRng, TryRngCore};

    // Generate random nonce
    let mut nonce = [0u8; PIE_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive encryption key and XChaCha20 nonce
    // tmp = BLAKE2b-MAC(key=wrapping_key, msg="paserk-wrap.pie." || nonce, len=56)
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, PIE_KDF_DOMAIN);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    // Ak = BLAKE2b-MAC(key=wrapping_key, msg="paserk-wrap.pie." || nonce || "auth-key-for-tag", len=32)
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_KDF_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut auth_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_AUTH_KEY_DOMAIN);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Encrypt the plaintext key
    // c = XChaCha20(key=Ek, nonce=n2, plaintext=ptk)
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &xchacha_nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag
    // t = BLAKE2b-MAC(key=Ak, msg=header || nonce || ciphertext, len=32)
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; PIE_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    Ok((nonce, ciphertext, tag))
}

/// Unwraps a local (symmetric) key using the PIE protocol for K2/K4.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for unwrapping
/// * `nonce` - The 32-byte nonce from the wrapped key
/// * `ciphertext` - The 32-byte encrypted key
/// * `tag` - The 32-byte authentication tag
/// * `header` - The PASERK header (e.g., "k4.local-wrap.pie.")
///
/// # Returns
///
/// The unwrapped 32-byte plaintext key.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pie_unwrap_local_k2k4(
    wrapping_key: &[u8; 32],
    nonce: &[u8; PIE_NONCE_SIZE],
    ciphertext: &[u8; 32],
    tag: &[u8; PIE_TAG_SIZE],
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use subtle::ConstantTimeEq;

    // Derive encryption key and XChaCha20 nonce
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, PIE_KDF_DOMAIN);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_KDF_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut auth_mac, nonce);
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_AUTH_KEY_DOMAIN);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Verify authentication tag
    // t2 = BLAKE2b-MAC(key=Ak, msg=header || nonce || ciphertext, len=32)
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, ciphertext);
    let computed_tag: [u8; PIE_TAG_SIZE] =
        <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    // Constant-time tag comparison
    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        let mut cipher = XChaCha20::new(&encryption_key.into(), &xchacha_nonce.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

/// Wraps a secret (signing) key using the PIE protocol for K2/K4.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for wrapping
/// * `plaintext_key` - The 64-byte Ed25519 secret key to wrap
/// * `header` - The PASERK header (e.g., "k4.secret-wrap.pie.")
///
/// # Returns
///
/// A tuple of (nonce, ciphertext, tag) where:
/// - nonce is 32 bytes
/// - ciphertext is 64 bytes (same size as plaintext)
/// - tag is 32 bytes
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pie_wrap_secret_k2k4(
    wrapping_key: &[u8; 32],
    plaintext_key: &[u8; 64],
    header: &str,
) -> PaserkResult<([u8; PIE_NONCE_SIZE], [u8; 64], [u8; PIE_TAG_SIZE])> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use rand_core::{OsRng, TryRngCore};

    // Generate random nonce
    let mut nonce = [0u8; PIE_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive encryption key and XChaCha20 nonce
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, PIE_KDF_DOMAIN);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_KDF_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut auth_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_AUTH_KEY_DOMAIN);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &xchacha_nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; PIE_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    Ok((nonce, ciphertext, tag))
}

/// Unwraps a secret (signing) key using the PIE protocol for K2/K4.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for unwrapping
/// * `nonce` - The 32-byte nonce from the wrapped key
/// * `ciphertext` - The 64-byte encrypted key
/// * `tag` - The 32-byte authentication tag
/// * `header` - The PASERK header (e.g., "k4.secret-wrap.pie.")
///
/// # Returns
///
/// The unwrapped 64-byte plaintext secret key.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn pie_unwrap_secret_k2k4(
    wrapping_key: &[u8; 32],
    nonce: &[u8; PIE_NONCE_SIZE],
    ciphertext: &[u8; 64],
    tag: &[u8; PIE_TAG_SIZE],
    header: &str,
) -> PaserkResult<[u8; 64]> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use subtle::ConstantTimeEq;

    // Derive encryption key and XChaCha20 nonce
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, PIE_KDF_DOMAIN);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_KDF_DOMAIN);
    <Blake2bMac32 as Update>::update(&mut auth_mac, nonce);
    <Blake2bMac32 as Update>::update(&mut auth_mac, PIE_AUTH_KEY_DOMAIN);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Verify authentication tag
    let mut tag_mac =
        <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key).map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, ciphertext);
    let computed_tag: [u8; PIE_TAG_SIZE] =
        <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    // Constant-time tag comparison
    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        let mut cipher = XChaCha20::new(&encryption_key.into(), &xchacha_nonce.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_wrap_unwrap_local_k4_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce, ciphertext, tag) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_wrap_unwrap_secret_k4_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 64];
        let header = "k4.secret-wrap.pie.";

        let (nonce, ciphertext, tag) =
            pie_wrap_secret_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped =
            pie_unwrap_secret_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_unwrap_local_wrong_key() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce, ciphertext, tag) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        let result =
            pie_unwrap_local_k2k4(&wrong_key, &nonce, &ciphertext, &tag, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_unwrap_local_modified_ciphertext() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce, mut ciphertext, tag) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Modify ciphertext
        ciphertext[0] ^= 0xff;

        let result =
            pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_unwrap_local_modified_tag() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce, ciphertext, mut tag) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Modify tag
        tag[0] ^= 0xff;

        let result =
            pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_unwrap_local_wrong_header() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";
        let wrong_header = "k4.secret-wrap.pie.";

        let (nonce, ciphertext, tag) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        let result =
            pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, wrong_header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_wrap_produces_different_nonces() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce1, _, _) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;
        let (nonce2, _, _) =
            pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Nonces should be different (probabilistically)
        assert_ne!(nonce1, nonce2);
        Ok(())
    }
}
