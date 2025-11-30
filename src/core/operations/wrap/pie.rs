//! PIE (Platform-Independent Encryption) protocol implementation.
//!
//! This module implements the PIE key wrapping protocol for PASERK.
//! - For K2/K4: Uses `XChaCha20` + `BLAKE2b`
//! - For K1/K3: Uses AES-256-CTR + HMAC-SHA384

#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
use crate::core::error::{PaserkError, PaserkResult};

/// Nonce size for PIE protocol (32 bytes).
pub const PIE_NONCE_SIZE: usize = 32;

/// Tag size for PIE protocol (32 bytes).
pub const PIE_TAG_SIZE: usize = 32;

/// Domain separation byte for PIE encryption key derivation (0x80).
#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
#[allow(dead_code)]
const PIE_ENCRYPTION_KEY_DOMAIN: u8 = 0x80;

/// Domain separation byte for PIE authentication key derivation (0x81).
#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
#[allow(dead_code)]
const PIE_AUTH_KEY_DOMAIN: u8 = 0x81;

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

    // Type aliases for BLAKE2b variants
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;

    // Generate random nonce
    let mut nonce = [0u8; PIE_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive encryption key and XChaCha20 nonce
    // x = BLAKE2b-MAC(key=wrapping_key, msg=0x80 || nonce, len=56)
    // Ek = x[0:32], n2 = x[32:56]
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &[PIE_ENCRYPTION_KEY_DOMAIN]);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    // Ak = BLAKE2b-MAC(key=wrapping_key, msg=0x81 || nonce, len=32)
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, &[PIE_AUTH_KEY_DOMAIN]);
    <Blake2bMac32 as Update>::update(&mut auth_mac, &nonce);
    let mut auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Encrypt the plaintext key
    // c = XChaCha20(key=Ek, nonce=n2, plaintext=ptk)
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &xchacha_nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag
    // t = BLAKE2b-MAC(key=Ak, msg=header || nonce || ciphertext, len=32)
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; PIE_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    // Zeroize sensitive key material
    zeroize::Zeroize::zeroize(&mut encryption_key);
    zeroize::Zeroize::zeroize(&mut xchacha_nonce);
    zeroize::Zeroize::zeroize(&mut auth_key);

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

    // Type aliases for BLAKE2b variants
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;

    // Derive encryption key and XChaCha20 nonce
    // x = BLAKE2b-MAC(key=wrapping_key, msg=0x80 || nonce, len=56)
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &[PIE_ENCRYPTION_KEY_DOMAIN]);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    // Ak = BLAKE2b-MAC(key=wrapping_key, msg=0x81 || nonce, len=32)
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, &[PIE_AUTH_KEY_DOMAIN]);
    <Blake2bMac32 as Update>::update(&mut auth_mac, nonce);
    let mut auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Verify authentication tag
    // t2 = BLAKE2b-MAC(key=Ak, msg=header || nonce || ciphertext, len=32)
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
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

        // Zeroize sensitive key material
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut xchacha_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Ok(plaintext)
    } else {
        // Zeroize sensitive key material even on error path
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut xchacha_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

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

    // Type aliases for BLAKE2b variants
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;

    // Generate random nonce
    let mut nonce = [0u8; PIE_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive encryption key and XChaCha20 nonce
    // x = BLAKE2b-MAC(key=wrapping_key, msg=0x80 || nonce, len=56)
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &[PIE_ENCRYPTION_KEY_DOMAIN]);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    // Ak = BLAKE2b-MAC(key=wrapping_key, msg=0x81 || nonce, len=32)
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, &[PIE_AUTH_KEY_DOMAIN]);
    <Blake2bMac32 as Update>::update(&mut auth_mac, &nonce);
    let mut auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &xchacha_nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag
    // t = BLAKE2b-MAC(key=Ak, msg=header || nonce || ciphertext, len=32)
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &nonce);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; PIE_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    // Zeroize sensitive key material
    zeroize::Zeroize::zeroize(&mut encryption_key);
    zeroize::Zeroize::zeroize(&mut xchacha_nonce);
    zeroize::Zeroize::zeroize(&mut auth_key);

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

    // Type aliases for BLAKE2b variants
    type Blake2bMac56 = Blake2bMac<blake2::digest::consts::U56>;
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;

    // Derive encryption key and XChaCha20 nonce
    // x = BLAKE2b-MAC(key=wrapping_key, msg=0x80 || nonce, len=56)
    let mut kdf_mac = <Blake2bMac56 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac56 as Update>::update(&mut kdf_mac, &[PIE_ENCRYPTION_KEY_DOMAIN]);
    <Blake2bMac56 as Update>::update(&mut kdf_mac, nonce);
    let tmp = <Blake2bMac56 as FixedOutput>::finalize_fixed(kdf_mac);

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut xchacha_nonce = [0u8; 24];
    xchacha_nonce.copy_from_slice(&tmp[32..56]);

    // Derive authentication key
    // Ak = BLAKE2b-MAC(key=wrapping_key, msg=0x81 || nonce, len=32)
    let mut auth_mac = <Blake2bMac32 as KeyInit>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut auth_mac, &[PIE_AUTH_KEY_DOMAIN]);
    <Blake2bMac32 as Update>::update(&mut auth_mac, nonce);
    let mut auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(auth_mac).into();

    // Verify authentication tag
    // t2 = BLAKE2b-MAC(key=Ak, msg=header || nonce || ciphertext, len=32)
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
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

        // Zeroize sensitive key material
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut xchacha_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Ok(plaintext)
    } else {
        // Zeroize sensitive key material even on error path
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut xchacha_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Err(PaserkError::AuthenticationFailed)
    }
}

// =============================================================================
// K1/K3 PIE Protocol Implementation (AES-256-CTR + HMAC-SHA384)
// =============================================================================

/// Nonce size for K1/K3 PIE protocol (32 bytes).
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
pub const PIE_K1K3_NONCE_SIZE: usize = 32;

/// Tag size for K1/K3 PIE protocol (48 bytes - HMAC-SHA384).
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
pub const PIE_K1K3_TAG_SIZE: usize = 48;

/// Domain separation byte for K1/K3 PIE encryption key derivation (0x80).
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
const PIE_K1K3_ENCRYPTION_KEY_DOMAIN: u8 = 0x80;

/// Domain separation byte for K1/K3 PIE authentication key derivation (0x81).
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
const PIE_K1K3_AUTH_KEY_DOMAIN: u8 = 0x81;

/// Derives encryption and authentication keys for K1/K3 PIE using HMAC-SHA384.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric wrapping key
/// * `nonce` - The 32-byte random nonce
///
/// # Returns
///
/// A tuple of (`encryption_key`, `aes_nonce`, `auth_key`) where:
/// - `encryption_key` is 32 bytes
/// - `aes_nonce` is 16 bytes
/// - `auth_key` is 48 bytes (full HMAC-SHA384 output)
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
fn derive_pie_keys_k1k3(
    wrapping_key: &[u8; 32],
    nonce: &[u8; PIE_K1K3_NONCE_SIZE],
) -> PaserkResult<([u8; 32], [u8; 16], [u8; 48])> {
    use hmac::{Hmac, Mac};
    use sha2::Sha384;

    // Derive tmp = HMAC-SHA384(key=wrapping_key, msg=0x80 || nonce)
    // Use first 32 bytes as Ek, next 16 bytes as AES-CTR nonce
    let mut kdf_mac = <Hmac<Sha384> as Mac>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    kdf_mac.update(&[PIE_K1K3_ENCRYPTION_KEY_DOMAIN]);
    kdf_mac.update(nonce);
    let tmp = kdf_mac.finalize().into_bytes();

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&tmp[..32]);

    let mut aes_nonce = [0u8; 16];
    aes_nonce.copy_from_slice(&tmp[32..48]);

    // Derive authentication key
    // Ak = HMAC-SHA384(key=wrapping_key, msg=0x81 || nonce)
    let mut auth_mac = <Hmac<Sha384> as Mac>::new_from_slice(wrapping_key)
        .map_err(|_| PaserkError::CryptoError)?;
    auth_mac.update(&[PIE_K1K3_AUTH_KEY_DOMAIN]);
    auth_mac.update(nonce);
    let auth_key: [u8; 48] = auth_mac.finalize().into_bytes().into();

    Ok((encryption_key, aes_nonce, auth_key))
}

/// Computes the authentication tag for K1/K3 PIE using HMAC-SHA384.
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
fn compute_pie_tag_k1k3(
    auth_key: &[u8; 48],
    header: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> PaserkResult<[u8; PIE_K1K3_TAG_SIZE]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha384;

    let mut tag_mac =
        <Hmac<Sha384> as Mac>::new_from_slice(auth_key).map_err(|_| PaserkError::CryptoError)?;
    tag_mac.update(header.as_bytes());
    tag_mac.update(nonce);
    tag_mac.update(ciphertext);
    Ok(tag_mac.finalize().into_bytes().into())
}

/// Encrypts/decrypts data using AES-256-CTR for PIE.
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
fn aes_ctr_apply(key: &[u8; 32], nonce: &[u8; 16], data: &mut [u8]) {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;

    type Aes256Ctr = Ctr128BE<aes::Aes256>;
    let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
}

/// Wraps a local (symmetric) key using the PIE protocol for K1/K3.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for wrapping
/// * `plaintext_key` - The 32-byte key to wrap
/// * `header` - The PASERK header (e.g., "k3.local-wrap.pie.")
///
/// # Returns
///
/// A tuple of (nonce, ciphertext, tag) where:
/// - nonce is 32 bytes
/// - ciphertext is 32 bytes
/// - tag is 48 bytes (HMAC-SHA384)
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
pub fn pie_wrap_local_k1k3(
    wrapping_key: &[u8; 32],
    plaintext_key: &[u8; 32],
    header: &str,
) -> PaserkResult<([u8; PIE_K1K3_NONCE_SIZE], [u8; 32], [u8; PIE_K1K3_TAG_SIZE])> {
    use rand_core::{OsRng, TryRngCore};

    // Generate random nonce
    let mut nonce = [0u8; PIE_K1K3_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive keys
    let (mut encryption_key, mut aes_nonce, mut auth_key) =
        derive_pie_keys_k1k3(wrapping_key, &nonce)?;

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    aes_ctr_apply(&encryption_key, &aes_nonce, &mut ciphertext);

    // Compute authentication tag
    let tag = compute_pie_tag_k1k3(&auth_key, header, &nonce, &ciphertext)?;

    // Zeroize sensitive key material
    zeroize::Zeroize::zeroize(&mut encryption_key);
    zeroize::Zeroize::zeroize(&mut aes_nonce);
    zeroize::Zeroize::zeroize(&mut auth_key);

    Ok((nonce, ciphertext, tag))
}

/// Unwraps a local (symmetric) key using the PIE protocol for K1/K3.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for unwrapping
/// * `nonce` - The 32-byte nonce from the wrapped key
/// * `ciphertext` - The 32-byte encrypted key
/// * `tag` - The 48-byte authentication tag
/// * `header` - The PASERK header (e.g., "k3.local-wrap.pie.")
///
/// # Returns
///
/// The unwrapped 32-byte plaintext key.
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
pub fn pie_unwrap_local_k1k3(
    wrapping_key: &[u8; 32],
    nonce: &[u8; PIE_K1K3_NONCE_SIZE],
    ciphertext: &[u8; 32],
    tag: &[u8; PIE_K1K3_TAG_SIZE],
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use subtle::ConstantTimeEq;

    // Derive keys
    let (mut encryption_key, mut aes_nonce, mut auth_key) =
        derive_pie_keys_k1k3(wrapping_key, nonce)?;

    // Verify authentication tag
    let computed_tag = compute_pie_tag_k1k3(&auth_key, header, nonce, ciphertext)?;

    // Constant-time tag comparison
    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        aes_ctr_apply(&encryption_key, &aes_nonce, &mut plaintext);

        // Zeroize sensitive key material
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut aes_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Ok(plaintext)
    } else {
        // Zeroize sensitive key material even on error path
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut aes_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Err(PaserkError::AuthenticationFailed)
    }
}

/// Wraps a P-384 secret key using the PIE protocol for K3.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for wrapping
/// * `plaintext_key` - The 48-byte P-384 secret key to wrap
/// * `header` - The PASERK header (e.g., "k3.secret-wrap.pie.")
///
/// # Returns
///
/// A tuple of (nonce, ciphertext, tag) where:
/// - nonce is 32 bytes
/// - ciphertext is 48 bytes
/// - tag is 48 bytes (HMAC-SHA384)
#[cfg(feature = "k3")]
pub fn pie_wrap_secret_k3(
    wrapping_key: &[u8; 32],
    plaintext_key: &[u8; 48],
    header: &str,
) -> PaserkResult<([u8; PIE_K1K3_NONCE_SIZE], [u8; 48], [u8; PIE_K1K3_TAG_SIZE])> {
    use rand_core::{OsRng, TryRngCore};

    // Generate random nonce
    let mut nonce = [0u8; PIE_K1K3_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| PaserkError::CryptoError)?;

    // Derive keys
    let (mut encryption_key, mut aes_nonce, mut auth_key) =
        derive_pie_keys_k1k3(wrapping_key, &nonce)?;

    // Encrypt the plaintext key
    let mut ciphertext = *plaintext_key;
    aes_ctr_apply(&encryption_key, &aes_nonce, &mut ciphertext);

    // Compute authentication tag
    let tag = compute_pie_tag_k1k3(&auth_key, header, &nonce, &ciphertext)?;

    // Zeroize sensitive key material
    zeroize::Zeroize::zeroize(&mut encryption_key);
    zeroize::Zeroize::zeroize(&mut aes_nonce);
    zeroize::Zeroize::zeroize(&mut auth_key);

    Ok((nonce, ciphertext, tag))
}

/// Unwraps a P-384 secret key using the PIE protocol for K3.
///
/// # Arguments
///
/// * `wrapping_key` - The 32-byte symmetric key used for unwrapping
/// * `nonce` - The 32-byte nonce from the wrapped key
/// * `ciphertext` - The 48-byte encrypted key
/// * `tag` - The 48-byte authentication tag
/// * `header` - The PASERK header (e.g., "k3.secret-wrap.pie.")
///
/// # Returns
///
/// The unwrapped 48-byte P-384 secret key.
#[cfg(feature = "k3")]
pub fn pie_unwrap_secret_k3(
    wrapping_key: &[u8; 32],
    nonce: &[u8; PIE_K1K3_NONCE_SIZE],
    ciphertext: &[u8; 48],
    tag: &[u8; PIE_K1K3_TAG_SIZE],
    header: &str,
) -> PaserkResult<[u8; 48]> {
    use subtle::ConstantTimeEq;

    // Derive keys
    let (mut encryption_key, mut aes_nonce, mut auth_key) =
        derive_pie_keys_k1k3(wrapping_key, nonce)?;

    // Verify authentication tag
    let computed_tag = compute_pie_tag_k1k3(&auth_key, header, nonce, ciphertext)?;

    // Constant-time tag comparison
    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let mut plaintext = *ciphertext;
        aes_ctr_apply(&encryption_key, &aes_nonce, &mut plaintext);

        // Zeroize sensitive key material
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut aes_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Ok(plaintext)
    } else {
        // Zeroize sensitive key material even on error path
        zeroize::Zeroize::zeroize(&mut encryption_key);
        zeroize::Zeroize::zeroize(&mut aes_nonce);
        zeroize::Zeroize::zeroize(&mut auth_key);

        Err(PaserkError::AuthenticationFailed)
    }
}

#[cfg(test)]
#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
#[allow(deprecated)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_wrap_unwrap_local_k4_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce, ciphertext, tag) = pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped = pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_wrap_unwrap_secret_k4_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 64];
        let header = "k4.secret-wrap.pie.";

        let (nonce, ciphertext, tag) = pie_wrap_secret_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped = pie_unwrap_secret_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

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

        let (nonce, ciphertext, tag) = pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        let result = pie_unwrap_local_k2k4(&wrong_key, &nonce, &ciphertext, &tag, header);

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

        let result = pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header);

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

        let result = pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, header);

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

        let (nonce, ciphertext, tag) = pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        let result = pie_unwrap_local_k2k4(&wrapping_key, &nonce, &ciphertext, &tag, wrong_header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_pie_wrap_produces_different_nonces() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k4.local-wrap.pie.";

        let (nonce1, _, _) = pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;
        let (nonce2, _, _) = pie_wrap_local_k2k4(&wrapping_key, &plaintext_key, header)?;

        // Nonces should be different (probabilistically)
        assert_ne!(nonce1, nonce2);
        Ok(())
    }

    // =========================================================================
    // K1/K3 PIE Tests
    // =========================================================================

    #[test]
    #[cfg(feature = "k3")]
    fn test_pie_wrap_unwrap_local_k3_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k3.local-wrap.pie.";

        let (nonce, ciphertext, tag) = pie_wrap_local_k1k3(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped = pie_unwrap_local_k1k3(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_pie_wrap_unwrap_local_k1_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k1.local-wrap.pie.";

        let (nonce, ciphertext, tag) = pie_wrap_local_k1k3(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped = pie_unwrap_local_k1k3(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pie_wrap_unwrap_secret_k3_roundtrip() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 48];
        let header = "k3.secret-wrap.pie.";

        let (nonce, ciphertext, tag) = pie_wrap_secret_k3(&wrapping_key, &plaintext_key, header)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext_key);

        let unwrapped = pie_unwrap_secret_k3(&wrapping_key, &nonce, &ciphertext, &tag, header)?;

        assert_eq!(unwrapped, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pie_k1k3_unwrap_wrong_key() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k3.local-wrap.pie.";

        let (nonce, ciphertext, tag) = pie_wrap_local_k1k3(&wrapping_key, &plaintext_key, header)?;

        let result = pie_unwrap_local_k1k3(&wrong_key, &nonce, &ciphertext, &tag, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pie_k1k3_unwrap_modified_tag() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k3.local-wrap.pie.";

        let (nonce, ciphertext, mut tag) =
            pie_wrap_local_k1k3(&wrapping_key, &plaintext_key, header)?;

        // Modify tag
        tag[0] ^= 0xff;

        let result = pie_unwrap_local_k1k3(&wrapping_key, &nonce, &ciphertext, &tag, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pie_k1k3_tag_size() {
        // K1/K3 uses HMAC-SHA384 with 48-byte tags
        assert_eq!(PIE_K1K3_TAG_SIZE, 48);
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_pie_k1k3_produces_different_nonces() -> PaserkResult<()> {
        let wrapping_key = [0x42u8; 32];
        let plaintext_key = [0x13u8; 32];
        let header = "k3.local-wrap.pie.";

        let (nonce1, _, _) = pie_wrap_local_k1k3(&wrapping_key, &plaintext_key, header)?;
        let (nonce2, _, _) = pie_wrap_local_k1k3(&wrapping_key, &plaintext_key, header)?;

        // Nonces should be different (probabilistically)
        assert_ne!(nonce1, nonce2);
        Ok(())
    }
}
