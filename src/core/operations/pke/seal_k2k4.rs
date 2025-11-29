//! X25519-based seal/unseal implementation for K2/K4.
//!
//! This module implements public key encryption using:
//! - X25519 for key exchange
//! - BLAKE2b for key derivation
//! - XChaCha20 for symmetric encryption

use crate::core::error::{PaserkError, PaserkResult};

/// Size of the ephemeral public key (X25519).
pub const EPHEMERAL_PK_SIZE: usize = 32;

/// Size of the sealed ciphertext (encrypted 32-byte key).
pub const SEAL_CIPHERTEXT_SIZE: usize = 32;

/// Size of the authentication tag.
pub const SEAL_TAG_SIZE: usize = 32;

/// Total size of sealed data: ephemeral_pk || ciphertext || tag.
pub const SEAL_DATA_SIZE: usize = EPHEMERAL_PK_SIZE + SEAL_CIPHERTEXT_SIZE + SEAL_TAG_SIZE;

/// Output type for seal operation: (ephemeral_pk, ciphertext, tag).
pub(crate) type SealOutput = ([u8; EPHEMERAL_PK_SIZE], [u8; SEAL_CIPHERTEXT_SIZE], [u8; SEAL_TAG_SIZE]);

/// Domain separation for seal encryption key derivation.
const SEAL_EK_DOMAIN: &[u8] = b"paserk.seal.k4";

/// Domain separation for seal authentication key derivation.
const SEAL_AK_DOMAIN: &[u8] = b"paserk.seal.k4.auth";

/// Seals (encrypts) a symmetric key with a recipient's public key.
///
/// This uses X25519 ECDH to establish a shared secret, then derives
/// encryption and authentication keys using BLAKE2b, encrypts the
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
/// A tuple of (ephemeral_public_key, ciphertext, tag).
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn seal_k2k4(
    plaintext_key: &[u8; 32],
    recipient_pk: &[u8; 32],
    header: &str,
) -> PaserkResult<SealOutput> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
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

    // Derive encryption key: Ek = BLAKE2b(shared_secret || ephemeral_pk || recipient_pk, domain)
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;

    let mut ek_hasher = <Blake2bMac32 as KeyInit>::new_from_slice(SEAL_EK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ek_hasher, shared_secret.as_bytes());
    <Blake2bMac32 as Update>::update(&mut ek_hasher, &ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut ek_hasher, recipient_pk);
    let encryption_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ek_hasher).into();

    // Derive authentication key
    let mut ak_hasher = <Blake2bMac32 as KeyInit>::new_from_slice(SEAL_AK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ak_hasher, shared_secret.as_bytes());
    <Blake2bMac32 as Update>::update(&mut ak_hasher, &ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut ak_hasher, recipient_pk);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ak_hasher).into();

    // Encrypt the plaintext key with XChaCha20 (using zeros as nonce since Ek is unique per seal)
    let nonce = [0u8; 24];
    let mut ciphertext = *plaintext_key;
    let mut cipher = XChaCha20::new(&encryption_key.into(), &nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag: tag = BLAKE2b-MAC(Ak, header || ephemeral_pk || ciphertext)
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut tag_mac, &ciphertext);
    let tag: [u8; SEAL_TAG_SIZE] = <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    // Zeroize sensitive data
    zeroize::Zeroize::zeroize(&mut ephemeral_secret_bytes);

    Ok((ephemeral_pk, ciphertext, tag))
}

/// Unseals (decrypts) a symmetric key using the recipient's secret key.
///
/// # Arguments
///
/// * `ephemeral_pk` - The ephemeral public key from the sealed data
/// * `ciphertext` - The encrypted key material
/// * `tag` - The authentication tag
/// * `recipient_sk` - The recipient's 64-byte Ed25519 secret key (will be converted to X25519)
/// * `header` - The PASERK header (e.g., "k4.seal.")
///
/// # Returns
///
/// The unsealed 32-byte symmetric key.
#[cfg(any(feature = "k2", feature = "k4"))]
pub fn unseal_k2k4(
    ephemeral_pk: &[u8; EPHEMERAL_PK_SIZE],
    ciphertext: &[u8; SEAL_CIPHERTEXT_SIZE],
    tag: &[u8; SEAL_TAG_SIZE],
    recipient_sk: &[u8; 64],
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
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

    // Derive encryption key
    type Blake2bMac32 = Blake2bMac<blake2::digest::consts::U32>;

    let mut ek_hasher = <Blake2bMac32 as KeyInit>::new_from_slice(SEAL_EK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ek_hasher, shared_secret.as_bytes());
    <Blake2bMac32 as Update>::update(&mut ek_hasher, ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut ek_hasher, &recipient_pk);
    let encryption_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ek_hasher).into();

    // Derive authentication key
    let mut ak_hasher = <Blake2bMac32 as KeyInit>::new_from_slice(SEAL_AK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut ak_hasher, shared_secret.as_bytes());
    <Blake2bMac32 as Update>::update(&mut ak_hasher, ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut ak_hasher, &recipient_pk);
    let auth_key: [u8; 32] = <Blake2bMac32 as FixedOutput>::finalize_fixed(ak_hasher).into();

    // Verify authentication tag
    let mut tag_mac = <Blake2bMac32 as KeyInit>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    <Blake2bMac32 as Update>::update(&mut tag_mac, header.as_bytes());
    <Blake2bMac32 as Update>::update(&mut tag_mac, ephemeral_pk);
    <Blake2bMac32 as Update>::update(&mut tag_mac, ciphertext);
    let computed_tag: [u8; SEAL_TAG_SIZE] =
        <Blake2bMac32 as FixedOutput>::finalize_fixed(tag_mac).into();

    if computed_tag.ct_eq(tag).into() {
        // Decrypt the ciphertext
        let nonce = [0u8; 24];
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
    fn generate_test_keypair() -> (ed25519_dalek::SigningKey, [u8; 64], [u8; 32]) {
        use ed25519_dalek::SigningKey;
        use rand_core::{OsRng, TryRngCore};
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate random seed bytes using our OsRng
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).expect("RNG should work");

        // Create Ed25519 signing key from seed
        let signing_key = SigningKey::from_bytes(&seed);
        let keypair_bytes = signing_key.to_keypair_bytes();

        // Convert to X25519 public key
        let x25519_secret = StaticSecret::from(signing_key.to_scalar_bytes());
        let x25519_public = PublicKey::from(&x25519_secret).to_bytes();

        (signing_key, keypair_bytes, x25519_public)
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_seal_unseal_roundtrip() {
        let (signing_key, secret_key_bytes, x25519_public) = generate_test_keypair();
        let _ = signing_key; // Silence unused warning

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (ephemeral_pk, ciphertext, tag) =
            seal_k2k4(&plaintext_key, &x25519_public, header)
                .expect("seal should succeed");

        assert_ne!(ciphertext, plaintext_key);

        let unsealed = unseal_k2k4(
            &ephemeral_pk,
            &ciphertext,
            &tag,
            &secret_key_bytes,
            header,
        )
        .expect("unseal should succeed");

        assert_eq!(unsealed, plaintext_key);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_seal_produces_different_output() {
        let (_, _, x25519_public) = generate_test_keypair();

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (epk1, ct1, tag1) = seal_k2k4(&plaintext_key, &x25519_public, header)
            .expect("seal should succeed");
        let (epk2, ct2, tag2) = seal_k2k4(&plaintext_key, &x25519_public, header)
            .expect("seal should succeed");

        // Different ephemeral keys should produce different outputs
        assert_ne!(epk1, epk2);
        assert_ne!(ct1, ct2);
        assert_ne!(tag1, tag2);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unseal_wrong_key() {
        let (_, _, x25519_public1) = generate_test_keypair();
        let (_, secret_key2_bytes, _) = generate_test_keypair();

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (ephemeral_pk, ciphertext, tag) =
            seal_k2k4(&plaintext_key, &x25519_public1, header)
                .expect("seal should succeed");

        // Try to unseal with wrong key
        let result = unseal_k2k4(
            &ephemeral_pk,
            &ciphertext,
            &tag,
            &secret_key2_bytes,
            header,
        );

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_unseal_modified_tag() {
        let (_, secret_key_bytes, x25519_public) = generate_test_keypair();

        let plaintext_key = [0x42u8; 32];
        let header = "k4.seal.";

        let (ephemeral_pk, ciphertext, mut tag) =
            seal_k2k4(&plaintext_key, &x25519_public, header)
                .expect("seal should succeed");

        tag[0] ^= 0xff;

        let result = unseal_k2k4(
            &ephemeral_pk,
            &ciphertext,
            &tag,
            &secret_key_bytes,
            header,
        );

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
    }
}
