//! X25519-based seal/unseal implementation for K2/K4.
//!
//! This module implements public key encryption using:
//! - X25519 for key exchange
//! - BLAKE2b for key derivation (unkeyed with domain bytes)
//! - XChaCha20 for symmetric encryption

use crate::core::error::{PaserkError, PaserkResult};

/// Size of the ephemeral public key (X25519).
pub const EPHEMERAL_PK_SIZE: usize = 32;

/// Size of the sealed ciphertext (encrypted 32-byte key).
pub const SEAL_CIPHERTEXT_SIZE: usize = 32;

/// Size of the authentication tag.
pub const SEAL_TAG_SIZE: usize = 32;

/// Size of the XChaCha20 nonce.
const SEAL_NONCE_SIZE: usize = 24;

/// Total size of sealed data: tag || ephemeral_pk || ciphertext.
pub const SEAL_DATA_SIZE: usize = SEAL_TAG_SIZE + EPHEMERAL_PK_SIZE + SEAL_CIPHERTEXT_SIZE;

/// Output type for seal operation: (tag, ephemeral_pk, ciphertext) - per spec order.
pub(crate) type SealOutput = ([u8; SEAL_TAG_SIZE], [u8; EPHEMERAL_PK_SIZE], [u8; SEAL_CIPHERTEXT_SIZE]);

/// Domain byte for encryption key derivation (0x01 per spec).
const SEAL_EK_DOMAIN_BYTE: u8 = 0x01;

/// Domain byte for authentication key derivation (0x02 per spec).
const SEAL_AK_DOMAIN_BYTE: u8 = 0x02;

/// Seals (encrypts) a symmetric key with a recipient's public key.
///
/// This uses X25519 ECDH to establish a shared secret, then derives
/// encryption and authentication keys using unkeyed BLAKE2b, encrypts the
/// symmetric key with XChaCha20, and computes a BLAKE2b-MAC tag.
///
/// # Arguments
///
/// * `plaintext_key` - The 32-byte symmetric key to seal
/// * `recipient_pk` - The recipient's 32-byte X25519 public key
/// * `header` - The PASERK header (e.g., "k4.seal.")
///
/// # Returns
///
/// A tuple of (tag, ephemeral_public_key, ciphertext) per spec order.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn seal_k2k4(
    plaintext_key: &[u8; 32],
    recipient_pk: &[u8; 32],
    header: &str,
) -> PaserkResult<SealOutput> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::{Blake2b, Blake2bMac};
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use rand_core::{OsRng, TryRngCore};
    use x25519_dalek::{PublicKey, StaticSecret};

    // Generate ephemeral keypair
    let mut ephemeral_secret_bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut ephemeral_secret_bytes)
        .map_err(|_| PaserkError::CryptoError)?;

    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_pk: [u8; 32] = PublicKey::from(&ephemeral_secret).to_bytes();

    // Compute shared secret via ECDH
    let recipient_public = PublicKey::from(*recipient_pk);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

    // Derive encryption key: Ek = BLAKE2b-256(0x01 || h || xk || epk || xpk) - UNKEYED
    type Blake2b32 = Blake2b<blake2::digest::consts::U32>;
    let mut ek_hasher = <Blake2b32 as Default>::default();
    <Blake2b32 as Update>::update(&mut ek_hasher, &[SEAL_EK_DOMAIN_BYTE]);
    <Blake2b32 as Update>::update(&mut ek_hasher, header.as_bytes());
    <Blake2b32 as Update>::update(&mut ek_hasher, shared_secret.as_bytes());
    <Blake2b32 as Update>::update(&mut ek_hasher, &ephemeral_pk);
    <Blake2b32 as Update>::update(&mut ek_hasher, recipient_pk);
    let encryption_key: [u8; 32] = <Blake2b32 as FixedOutput>::finalize_fixed(ek_hasher).into();

    // Derive authentication key: Ak = BLAKE2b-256(0x02 || h || xk || epk || xpk) - UNKEYED
    let mut ak_hasher = <Blake2b32 as Default>::default();
    <Blake2b32 as Update>::update(&mut ak_hasher, &[SEAL_AK_DOMAIN_BYTE]);
    <Blake2b32 as Update>::update(&mut ak_hasher, header.as_bytes());
    <Blake2b32 as Update>::update(&mut ak_hasher, shared_secret.as_bytes());
    <Blake2b32 as Update>::update(&mut ak_hasher, &ephemeral_pk);
    <Blake2b32 as Update>::update(&mut ak_hasher, recipient_pk);
    let auth_key: [u8; 32] = <Blake2b32 as FixedOutput>::finalize_fixed(ak_hasher).into();

    // Derive nonce: n = BLAKE2b-192(epk || xpk) - UNKEYED
    type Blake2b24 = Blake2b<blake2::digest::consts::U24>;
    let mut n_hasher = <Blake2b24 as Default>::default();
    <Blake2b24 as Update>::update(&mut n_hasher, &ephemeral_pk);
    <Blake2b24 as Update>::update(&mut n_hasher, recipient_pk);
    let nonce: [u8; SEAL_NONCE_SIZE] = <Blake2b24 as FixedOutput>::finalize_fixed(n_hasher).into();

    // Encrypt the plaintext key: edk = XChaCha20(pdk, Ek, n)
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag: t = BLAKE2b-MAC(h || epk || edk, key=Ak) - KEYED
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; SEAL_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    // Zeroize sensitive data
    zeroize::Zeroize::zeroize(&mut ephemeral_secret_bytes);

    // Return in spec order: (tag, ephemeral_pk, ciphertext)
    Ok((tag, ephemeral_pk, ciphertext))
}

/// Unseals (decrypts) a symmetric key using the recipient's secret key.
///
/// # Arguments
///
/// * `tag` - The authentication tag
/// * `ephemeral_pk` - The ephemeral public key from the sealed data
/// * `ciphertext` - The encrypted key material
/// * `recipient_sk` - The recipient's 64-byte Ed25519 secret key (will be converted to X25519)
/// * `header` - The PASERK header (e.g., "k4.seal.")
///
/// # Returns
///
/// The unsealed 32-byte symmetric key.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn unseal_k2k4(
    tag: &[u8; SEAL_TAG_SIZE],
    ephemeral_pk: &[u8; EPHEMERAL_PK_SIZE],
    ciphertext: &[u8; SEAL_CIPHERTEXT_SIZE],
    recipient_sk: &[u8; 64],
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::{Blake2b, Blake2bMac};
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::XChaCha20;
    use ed25519_dalek::SigningKey;
    use subtle::ConstantTimeEq;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Convert Ed25519 secret key to X25519 secret key
    // The Ed25519 secret key has format: [32-byte seed || 32-byte public key]
    // We use the seed to derive the X25519 secret
    let ed_secret = SigningKey::from_keypair_bytes(recipient_sk)
        .map_err(|_| PaserkError::InvalidKey)?;

    // Hash the Ed25519 seed to get the X25519 scalar (this is how dalek does it internally)
    let x25519_secret = StaticSecret::from(ed_secret.to_scalar_bytes());

    // Compute our public key for verification
    let recipient_pk: [u8; 32] = PublicKey::from(&x25519_secret).to_bytes();

    // Compute shared secret via ECDH
    let ephemeral_public = PublicKey::from(*ephemeral_pk);
    let shared_secret = x25519_secret.diffie_hellman(&ephemeral_public);

    // Derive encryption key: Ek = BLAKE2b-256(0x01 || h || xk || epk || xpk) - UNKEYED
    type Blake2b32 = Blake2b<blake2::digest::consts::U32>;
    let mut ek_hasher = <Blake2b32 as Default>::default();
    <Blake2b32 as Update>::update(&mut ek_hasher, &[SEAL_EK_DOMAIN_BYTE]);
    <Blake2b32 as Update>::update(&mut ek_hasher, header.as_bytes());
    <Blake2b32 as Update>::update(&mut ek_hasher, shared_secret.as_bytes());
    <Blake2b32 as Update>::update(&mut ek_hasher, ephemeral_pk);
    <Blake2b32 as Update>::update(&mut ek_hasher, &recipient_pk);
    let encryption_key: [u8; 32] = <Blake2b32 as FixedOutput>::finalize_fixed(ek_hasher).into();

    // Derive authentication key: Ak = BLAKE2b-256(0x02 || h || xk || epk || xpk) - UNKEYED
    let mut ak_hasher = <Blake2b32 as Default>::default();
    <Blake2b32 as Update>::update(&mut ak_hasher, &[SEAL_AK_DOMAIN_BYTE]);
    <Blake2b32 as Update>::update(&mut ak_hasher, header.as_bytes());
    <Blake2b32 as Update>::update(&mut ak_hasher, shared_secret.as_bytes());
    <Blake2b32 as Update>::update(&mut ak_hasher, ephemeral_pk);
    <Blake2b32 as Update>::update(&mut ak_hasher, &recipient_pk);
    let auth_key: [u8; 32] = <Blake2b32 as FixedOutput>::finalize_fixed(ak_hasher).into();

    // Verify authentication tag: t = BLAKE2b-MAC(h || epk || edk, key=Ak) - KEYED
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut tag_mac, ciphertext);
    let computed_tag: [u8; SEAL_TAG_SIZE] =
        <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    if computed_tag.ct_eq(tag).into() {
        // Derive nonce: n = BLAKE2b-192(epk || xpk) - UNKEYED
        type Blake2b24 = Blake2b<blake2::digest::consts::U24>;
        let mut n_hasher = <Blake2b24 as Default>::default();
        <Blake2b24 as Update>::update(&mut n_hasher, ephemeral_pk);
        <Blake2b24 as Update>::update(&mut n_hasher, &recipient_pk);
        let nonce: [u8; SEAL_NONCE_SIZE] =
            <Blake2b24 as FixedOutput>::finalize_fixed(n_hasher).into();

        // Decrypt the ciphertext: pdk = XChaCha20(edk, Ek, n)
        let mut plaintext = *ciphertext;
        let mut cipher = XChaCha20::new(&encryption_key.into(), &nonce.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    } else {
        Err(PaserkError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to generate an Ed25519 keypair for testing.
    /// Uses our rand_core 0.9 OsRng to avoid version conflicts.
    #[cfg(feature = "k4")]
    fn generate_test_keypair() -> PaserkResult<(ed25519_dalek::SigningKey, [u8; 64], [u8; 32])> {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, TryRngCore};
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate random seed bytes using our OsRng
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).map_err(|_| PaserkError::CryptoError)?;

        // Create Ed25519 signing key from seed
        let signing_key = SigningKey::from_bytes(&seed);
        let keypair_bytes = signing_key.to_keypair_bytes();

        // Convert to X25519 public key
        let x25519_secret = StaticSecret::from(signing_key.to_scalar_bytes());
        let x25519_public = PublicKey::from(&x25519_secret).to_bytes();

        Ok((signing_key, keypair_bytes, x25519_public))
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_seal_unseal_roundtrip() -> PaserkResult<()> {
        let (signing_key, secret_key_bytes, x25519_public) = generate_test_keypair()?;
        let _ = signing_key; // Silence unused warning

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (tag, ephemeral_pk, ciphertext) =
            seal_k2k4(&plaintext_key, &x25519_public, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unsealed = unseal_k2k4(
            &tag,
            &ephemeral_pk,
            &ciphertext,
            &secret_key_bytes,
            header,
        )?;

        assert_eq!(unsealed, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_seal_produces_different_output() -> PaserkResult<()> {
        let (_, _, x25519_public) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (tag1, epk1, ct1) = seal_k2k4(&plaintext_key, &x25519_public, header)?;
        let (tag2, epk2, ct2) = seal_k2k4(&plaintext_key, &x25519_public, header)?;

        // Different ephemeral keys should produce different outputs
        assert_ne!(epk1, epk2);
        assert_ne!(ct1, ct2);
        assert_ne!(tag1, tag2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unseal_wrong_key() -> PaserkResult<()> {
        let (_, _, x25519_public1) = generate_test_keypair()?;
        let (_, secret_key2_bytes, _) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (tag, ephemeral_pk, ciphertext) =
            seal_k2k4(&plaintext_key, &x25519_public1, header)?;

        // Try to unseal with wrong key
        let result = unseal_k2k4(
            &tag,
            &ephemeral_pk,
            &ciphertext,
            &secret_key2_bytes,
            header,
        );

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unseal_modified_tag() -> PaserkResult<()> {
        let (_, secret_key_bytes, x25519_public) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (mut tag, ephemeral_pk, ciphertext) =
            seal_k2k4(&plaintext_key, &x25519_public, header)?;

        tag[0] ^= 0xff;

        let result = unseal_k2k4(
            &tag,
            &ephemeral_pk,
            &ciphertext,
            &secret_key_bytes,
            header,
        );

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }
}
