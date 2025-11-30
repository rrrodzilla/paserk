//! P-384 ECDH-based seal/unseal implementation for K3.
//!
//! This module implements public key encryption using:
//! - P-384 (secp384r1) for key exchange
//! - SHA-384 for key derivation
//! - AES-256-CTR for symmetric encryption
//! - HMAC-SHA384 for authentication

use crate::core::error::{PaserkError, PaserkResult};

/// Size of the ephemeral public key (P-384 compressed SEC1 format: 1 + 48 bytes).
pub const K3_EPHEMERAL_PK_SIZE: usize = 49;

/// Size of the sealed ciphertext (encrypted 32-byte key).
pub const K3_SEAL_CIPHERTEXT_SIZE: usize = 32;

/// Size of the authentication tag (HMAC-SHA384 = 48 bytes).
pub const K3_SEAL_TAG_SIZE: usize = 48;

/// Total size of sealed data: `ephemeral_pk` || ciphertext || tag.
pub const K3_SEAL_DATA_SIZE: usize = K3_EPHEMERAL_PK_SIZE + K3_SEAL_CIPHERTEXT_SIZE + K3_SEAL_TAG_SIZE;

/// Output type for seal operation: (`ephemeral_pk`, ciphertext, tag).
pub(crate) type K3SealOutput = ([u8; K3_EPHEMERAL_PK_SIZE], [u8; K3_SEAL_CIPHERTEXT_SIZE], [u8; K3_SEAL_TAG_SIZE]);

/// Domain separation for seal encryption key derivation.
const SEAL_EK_DOMAIN: &[u8] = b"paserk.seal.k3";

/// Domain separation for seal authentication key derivation.
const SEAL_AK_DOMAIN: &[u8] = b"paserk.seal.k3.auth";

/// Seals (encrypts) a symmetric key with a recipient's P-384 public key.
///
/// This uses P-384 ECDH to establish a shared secret, then derives
/// encryption and authentication keys using HKDF-SHA384, encrypts the
/// symmetric key with AES-256-CTR, and computes an HMAC-SHA384 tag.
///
/// # Arguments
///
/// * `plaintext_key` - The 32-byte symmetric key to seal
/// * `recipient_pk` - The recipient's P-384 public key in SEC1 compressed format
/// * `header` - The PASERK header (e.g., "k3.seal.")
///
/// # Returns
///
/// A tuple of (`ephemeral_public_key`, ciphertext, tag).
#[cfg(feature = "k3")]
pub fn seal_k3(
    plaintext_key: &[u8; 32],
    recipient_pk: &[u8; K3_EPHEMERAL_PK_SIZE],
    header: &str,
) -> PaserkResult<K3SealOutput> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr64BE;
    use hmac::{Hmac, Mac};
    use p384::ecdh::EphemeralSecret;
    use p384::elliptic_curve::rand_core::OsRng as P384OsRng;
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::{EncodedPoint, PublicKey};
    use sha2::Sha384;

    // Type aliases for cipher types
    type HmacSha384 = Hmac<Sha384>;
    type Aes256Ctr = Ctr64BE<aes::Aes256>;

    // Parse recipient's public key from SEC1 compressed format
    let recipient_point = EncodedPoint::from_bytes(recipient_pk)
        .map_err(|_| PaserkError::InvalidKey)?;
    let recipient_public = PublicKey::from_sec1_bytes(recipient_point.as_bytes())
        .map_err(|_| PaserkError::InvalidKey)?;

    // Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random(&mut P384OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    // Get ephemeral public key in compressed SEC1 format
    let ephemeral_point = ephemeral_public.to_encoded_point(true);
    let ephemeral_pk_bytes = ephemeral_point.as_bytes();
    let mut ephemeral_pk = [0u8; K3_EPHEMERAL_PK_SIZE];
    ephemeral_pk.copy_from_slice(ephemeral_pk_bytes);

    // Compute shared secret via ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    let shared_bytes = shared_secret.raw_secret_bytes();

    // Derive encryption key: Ek = HMAC-SHA384(domain, shared_secret || ephemeral_pk || recipient_pk)
    let mut ek_mac = <HmacSha384 as Mac>::new_from_slice(SEAL_EK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    ek_mac.update(shared_bytes);
    ek_mac.update(&ephemeral_pk);
    ek_mac.update(recipient_pk);
    let ek_result = ek_mac.finalize().into_bytes();
    // Use first 32 bytes for AES-256 key
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&ek_result[..32]);

    // Derive authentication key
    let mut ak_mac = <HmacSha384 as Mac>::new_from_slice(SEAL_AK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    ak_mac.update(shared_bytes);
    ak_mac.update(&ephemeral_pk);
    ak_mac.update(recipient_pk);
    let ak_result = ak_mac.finalize().into_bytes();
    // Use first 32 bytes for HMAC key (will be extended internally by HMAC)
    let mut auth_key = [0u8; 48];
    auth_key.copy_from_slice(&ak_result[..48]);

    // Encrypt the plaintext key with AES-256-CTR (using zeros as nonce since Ek is unique per seal)
    let nonce = [0u8; 16];
    let mut ciphertext = *plaintext_key;
    let mut cipher = Aes256Ctr::new(&encryption_key.into(), &nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Compute authentication tag: tag = HMAC-SHA384(Ak, header || ephemeral_pk || ciphertext)
    let mut tag_mac = <HmacSha384 as Mac>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    tag_mac.update(header.as_bytes());
    tag_mac.update(&ephemeral_pk);
    tag_mac.update(&ciphertext);
    let tag_result = tag_mac.finalize().into_bytes();
    let mut tag = [0u8; K3_SEAL_TAG_SIZE];
    tag.copy_from_slice(&tag_result[..K3_SEAL_TAG_SIZE]);

    // Zeroize sensitive data
    zeroize::Zeroize::zeroize(&mut encryption_key);
    zeroize::Zeroize::zeroize(&mut auth_key);

    Ok((ephemeral_pk, ciphertext, tag))
}

/// Unseals (decrypts) a symmetric key using the recipient's P-384 secret key.
///
/// # Arguments
///
/// * `ephemeral_pk` - The ephemeral public key from the sealed data
/// * `ciphertext` - The encrypted key material
/// * `tag` - The authentication tag
/// * `recipient_sk` - The recipient's P-384 secret key (48 bytes scalar)
/// * `header` - The PASERK header (e.g., "k3.seal.")
///
/// # Returns
///
/// The unsealed 32-byte symmetric key.
#[cfg(feature = "k3")]
pub fn unseal_k3(
    ephemeral_pk: &[u8; K3_EPHEMERAL_PK_SIZE],
    ciphertext: &[u8; K3_SEAL_CIPHERTEXT_SIZE],
    tag: &[u8; K3_SEAL_TAG_SIZE],
    recipient_sk: &[u8; 48],
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr64BE;
    use hmac::{Hmac, Mac};
    use p384::ecdh::diffie_hellman;
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use p384::{EncodedPoint, PublicKey, SecretKey};
    use sha2::Sha384;
    use subtle::ConstantTimeEq;

    // Type aliases for cipher types
    type HmacSha384 = Hmac<Sha384>;
    type Aes256Ctr = Ctr64BE<aes::Aes256>;

    // Parse recipient's secret key
    let recipient_secret = SecretKey::from_slice(recipient_sk)
        .map_err(|_| PaserkError::InvalidKey)?;

    // Compute recipient's P-384 public key for derivation
    let recipient_public = recipient_secret.public_key();
    let recipient_point = recipient_public.to_encoded_point(true);
    let mut p384_recipient_pk = [0u8; K3_EPHEMERAL_PK_SIZE];
    p384_recipient_pk.copy_from_slice(recipient_point.as_bytes());

    // Parse ephemeral public key
    let ephemeral_point = EncodedPoint::from_bytes(ephemeral_pk)
        .map_err(|_| PaserkError::InvalidKey)?;
    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_point.as_bytes())
        .map_err(|_| PaserkError::InvalidKey)?;

    // Compute shared secret via ECDH
    let shared_secret = diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let shared_bytes = shared_secret.raw_secret_bytes();

    // Derive encryption key
    let mut ek_mac = <HmacSha384 as Mac>::new_from_slice(SEAL_EK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    ek_mac.update(shared_bytes);
    ek_mac.update(ephemeral_pk);
    ek_mac.update(&p384_recipient_pk);
    let ek_result = ek_mac.finalize().into_bytes();
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&ek_result[..32]);

    // Derive authentication key
    let mut ak_mac = <HmacSha384 as Mac>::new_from_slice(SEAL_AK_DOMAIN)
        .map_err(|_| PaserkError::CryptoError)?;
    ak_mac.update(shared_bytes);
    ak_mac.update(ephemeral_pk);
    ak_mac.update(&p384_recipient_pk);
    let ak_result = ak_mac.finalize().into_bytes();
    let mut auth_key = [0u8; 48];
    auth_key.copy_from_slice(&ak_result[..48]);

    // Verify authentication tag
    let mut tag_mac = <HmacSha384 as Mac>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    tag_mac.update(header.as_bytes());
    tag_mac.update(ephemeral_pk);
    tag_mac.update(ciphertext);
    let computed_tag = tag_mac.finalize().into_bytes();

    let tag_valid: bool = computed_tag[..K3_SEAL_TAG_SIZE].ct_eq(tag).into();

    // Zeroize before potentially returning error
    zeroize::Zeroize::zeroize(&mut auth_key);

    if tag_valid {
        // Decrypt the ciphertext
        let nonce = [0u8; 16];
        let mut plaintext = *ciphertext;
        let mut cipher = Aes256Ctr::new(&encryption_key.into(), &nonce.into());
        cipher.apply_keystream(&mut plaintext);

        zeroize::Zeroize::zeroize(&mut encryption_key);
        Ok(plaintext)
    } else {
        zeroize::Zeroize::zeroize(&mut encryption_key);
        Err(PaserkError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to generate a P-384 keypair for testing.
    #[cfg(feature = "k3")]
    fn generate_test_keypair() -> PaserkResult<([u8; 48], [u8; K3_EPHEMERAL_PK_SIZE])> {
        use p384::elliptic_curve::rand_core::OsRng as P384OsRng;
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        use p384::SecretKey;

        let secret_key = SecretKey::random(&mut P384OsRng);
        let public_key = secret_key.public_key();

        let secret_bytes = secret_key.to_bytes();
        let mut sk = [0u8; 48];
        sk.copy_from_slice(&secret_bytes);

        let public_point = public_key.to_encoded_point(true);
        let mut pk = [0u8; K3_EPHEMERAL_PK_SIZE];
        pk.copy_from_slice(public_point.as_bytes());

        Ok((sk, pk))
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_seal_unseal_roundtrip() -> PaserkResult<()> {
        let (secret_key, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k3.seal.";

        let (ephemeral_pk, ciphertext, tag) = seal_k3(&plaintext_key, &public_key, header)?;

        assert_ne!(ciphertext, plaintext_key);

        let unsealed = unseal_k3(&ephemeral_pk, &ciphertext, &tag, &secret_key, header)?;

        assert_eq!(unsealed, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_seal_produces_different_output() -> PaserkResult<()> {
        let (_, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k3.seal.";

        let (epk1, ct1, tag1) = seal_k3(&plaintext_key, &public_key, header)?;
        let (epk2, ct2, tag2) = seal_k3(&plaintext_key, &public_key, header)?;

        // Different ephemeral keys should produce different outputs
        assert_ne!(epk1, epk2);
        assert_ne!(ct1, ct2);
        assert_ne!(tag1, tag2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_unseal_wrong_key() -> PaserkResult<()> {
        let (_, public_key1) = generate_test_keypair()?;
        let (secret_key2, _) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k3.seal.";

        let (ephemeral_pk, ciphertext, tag) = seal_k3(&plaintext_key, &public_key1, header)?;

        // Try to unseal with wrong key
        let result = unseal_k3(&ephemeral_pk, &ciphertext, &tag, &secret_key2, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_unseal_modified_tag() -> PaserkResult<()> {
        let (secret_key, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k3.seal.";

        let (ephemeral_pk, ciphertext, mut tag) = seal_k3(&plaintext_key, &public_key, header)?;

        tag[0] ^= 0xff;

        let result = unseal_k3(&ephemeral_pk, &ciphertext, &tag, &secret_key, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k3")]
    fn test_ephemeral_pk_size() -> PaserkResult<()> {
        let (_, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k3.seal.";

        let (ephemeral_pk, _, _) = seal_k3(&plaintext_key, &public_key, header)?;

        // P-384 compressed SEC1 format: 1 byte prefix + 48 bytes x-coordinate
        assert_eq!(ephemeral_pk.len(), 49);
        // Check it's in compressed format (prefix should be 0x02 or 0x03)
        assert!(ephemeral_pk[0] == 0x02 || ephemeral_pk[0] == 0x03);
        Ok(())
    }
}
