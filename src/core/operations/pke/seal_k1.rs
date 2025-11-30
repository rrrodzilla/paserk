//! RSA-KEM based seal/unseal implementation for K1.
//!
//! This module implements public key encryption using:
//! - RSA-4096 for key encapsulation
//! - SHA-384 for key derivation
//! - AES-256-CTR for symmetric encryption
//! - HMAC-SHA384 for authentication

use crate::core::error::{PaserkError, PaserkResult};

/// Size of the RSA ciphertext (4096-bit RSA = 512 bytes).
pub const K1_RSA_CIPHERTEXT_SIZE: usize = 512;

/// Size of the sealed ciphertext (encrypted 32-byte key).
pub const K1_SEAL_CIPHERTEXT_SIZE: usize = 32;

/// Size of the authentication tag (HMAC-SHA384 = 48 bytes).
pub const K1_SEAL_TAG_SIZE: usize = 48;

/// Total size of sealed data: tag || edk || c (per PASERK spec order).
pub const K1_SEAL_DATA_SIZE: usize = K1_SEAL_TAG_SIZE + K1_SEAL_CIPHERTEXT_SIZE + K1_RSA_CIPHERTEXT_SIZE;

/// Output type for seal operation: (tag, `encrypted_data_key`, `rsa_ciphertext`).
pub(crate) type K1SealOutput = (
    [u8; K1_SEAL_TAG_SIZE],
    [u8; K1_SEAL_CIPHERTEXT_SIZE],
    [u8; K1_RSA_CIPHERTEXT_SIZE],
);

/// Domain separation byte for encryption key derivation.
const EK_DOMAIN_BYTE: u8 = 0x01;

/// Domain separation byte for authentication key derivation.
const AK_DOMAIN_BYTE: u8 = 0x02;

/// Seals (encrypts) a symmetric key with a recipient's RSA-4096 public key.
///
/// This uses RSA-KEM to encapsulate a random value, then derives
/// encryption and authentication keys using HMAC-SHA384, encrypts the
/// symmetric key with AES-256-CTR, and computes an HMAC-SHA384 tag.
///
/// # Arguments
///
/// * `plaintext_key` - The 32-byte symmetric key to seal
/// * `recipient_pk` - The recipient's RSA-4096 public key
/// * `header` - The PASERK header (e.g., "k1.seal.")
///
/// # Returns
///
/// A tuple of (tag, `encrypted_data_key`, `rsa_ciphertext`).
#[cfg(feature = "k1-insecure")]
pub fn seal_k1(
    plaintext_key: &[u8; 32],
    recipient_pk: &rsa::RsaPublicKey,
    header: &str,
) -> PaserkResult<K1SealOutput> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr64BE;
    use hmac::{Hmac, Mac};
    use rand_core::{OsRng, TryRngCore};
    use rsa::traits::PublicKeyParts;
    use rsa::BigUint;
    use sha2::{Digest, Sha384};

    // Type aliases for cipher types
    type HmacSha384 = Hmac<Sha384>;
    type Aes256Ctr = Ctr64BE<aes::Aes256>;

    // Verify the public key has a 4096-bit modulus
    let n = recipient_pk.n();
    if n.bits() != 4096 {
        return Err(PaserkError::InvalidKey);
    }

    // Generate random 512 bytes for r
    // Clear leftmost bit and set second bit to ensure r^e wraps modulus
    let mut r_bytes = [0u8; 512];
    OsRng
        .try_fill_bytes(&mut r_bytes)
        .map_err(|_| PaserkError::CryptoError)?;
    r_bytes[0] &= 0x7F; // Clear leftmost bit
    r_bytes[0] |= 0x40; // Set second bit

    // RSA encrypt: c = r^e (mod n)
    let r = BigUint::from_bytes_be(&r_bytes);
    let e = recipient_pk.e();
    let c_bigint = r.modpow(e, n);
    let c_bytes_raw = c_bigint.to_bytes_be();

    // Pad c to 512 bytes if needed (left-pad with zeros)
    let mut c = [0u8; K1_RSA_CIPHERTEXT_SIZE];
    let start = K1_RSA_CIPHERTEXT_SIZE.saturating_sub(c_bytes_raw.len());
    c[start..].copy_from_slice(&c_bytes_raw);

    // Compute SHA384(c) for use as HMAC key
    let c_hash = Sha384::digest(c);

    // Derive encryption key and counter: HMAC-SHA384(msg = 0x01 || h || r, key = SHA384(c))
    let mut ek_mac = <HmacSha384 as Mac>::new_from_slice(&c_hash)
        .map_err(|_| PaserkError::CryptoError)?;
    ek_mac.update(&[EK_DOMAIN_BYTE]);
    ek_mac.update(header.as_bytes());
    ek_mac.update(&r_bytes);
    let ek_result = ek_mac.finalize().into_bytes();

    // First 32 bytes = encryption key, next 16 bytes = counter
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&ek_result[..32]);
    let mut counter = [0u8; 16];
    counter.copy_from_slice(&ek_result[32..48]);

    // Derive authentication key: HMAC-SHA384(msg = 0x02 || h || r, key = SHA384(c))
    let mut ak_mac = <HmacSha384 as Mac>::new_from_slice(&c_hash)
        .map_err(|_| PaserkError::CryptoError)?;
    ak_mac.update(&[AK_DOMAIN_BYTE]);
    ak_mac.update(header.as_bytes());
    ak_mac.update(&r_bytes);
    let ak_result = ak_mac.finalize().into_bytes();
    let mut auth_key = [0u8; 48];
    auth_key.copy_from_slice(&ak_result[..48]);

    // Encrypt the plaintext key with AES-256-CTR
    let mut edk = *plaintext_key;
    let mut cipher = Aes256Ctr::new(&encryption_key.into(), &counter.into());
    cipher.apply_keystream(&mut edk);

    // Compute authentication tag: t = HMAC-SHA384(msg = h || c || edk, key = Ak)
    let mut tag_mac = <HmacSha384 as Mac>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    tag_mac.update(header.as_bytes());
    tag_mac.update(&c);
    tag_mac.update(&edk);
    let tag_result = tag_mac.finalize().into_bytes();
    let mut tag = [0u8; K1_SEAL_TAG_SIZE];
    tag.copy_from_slice(&tag_result[..K1_SEAL_TAG_SIZE]);

    // Zeroize sensitive data
    zeroize::Zeroize::zeroize(&mut r_bytes);
    zeroize::Zeroize::zeroize(&mut encryption_key);
    zeroize::Zeroize::zeroize(&mut auth_key);

    Ok((tag, edk, c))
}

/// Unseals (decrypts) a symmetric key using the recipient's RSA-4096 secret key.
///
/// # Arguments
///
/// * `tag` - The authentication tag
/// * `edk` - The encrypted data key
/// * `c` - The RSA ciphertext
/// * `recipient_sk` - The recipient's RSA-4096 secret key
/// * `header` - The PASERK header (e.g., "k1.seal.")
///
/// # Returns
///
/// The unsealed 32-byte symmetric key.
#[cfg(feature = "k1-insecure")]
pub fn unseal_k1(
    tag: &[u8; K1_SEAL_TAG_SIZE],
    edk: &[u8; K1_SEAL_CIPHERTEXT_SIZE],
    c: &[u8; K1_RSA_CIPHERTEXT_SIZE],
    recipient_sk: &rsa::RsaPrivateKey,
    header: &str,
) -> PaserkResult<[u8; 32]> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr64BE;
    use hmac::{Hmac, Mac};
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::BigUint;
    use sha2::{Digest, Sha384};
    use subtle::ConstantTimeEq;

    // Type aliases for cipher types
    type HmacSha384 = Hmac<Sha384>;
    type Aes256Ctr = Ctr64BE<aes::Aes256>;

    // Verify the secret key has a 4096-bit modulus
    let n = recipient_sk.n();
    if n.bits() != 4096 {
        return Err(PaserkError::InvalidKey);
    }

    // RSA decrypt: r = c^d (mod n)
    let c_bigint = BigUint::from_bytes_be(c);
    let d = recipient_sk.d();
    let r_bigint = c_bigint.modpow(d, n);
    let r_bytes_raw = r_bigint.to_bytes_be();

    // Pad r to 512 bytes if needed
    let mut r_bytes = [0u8; 512];
    let start = 512_usize.saturating_sub(r_bytes_raw.len());
    r_bytes[start..].copy_from_slice(&r_bytes_raw);

    // Compute SHA384(c) for use as HMAC key
    let c_hash = Sha384::digest(c);

    // Derive authentication key: HMAC-SHA384(msg = 0x02 || h || r, key = SHA384(c))
    let mut ak_mac = <HmacSha384 as Mac>::new_from_slice(&c_hash)
        .map_err(|_| PaserkError::CryptoError)?;
    ak_mac.update(&[AK_DOMAIN_BYTE]);
    ak_mac.update(header.as_bytes());
    ak_mac.update(&r_bytes);
    let ak_result = ak_mac.finalize().into_bytes();
    let mut auth_key = [0u8; 48];
    auth_key.copy_from_slice(&ak_result[..48]);

    // Verify authentication tag
    let mut tag_mac = <HmacSha384 as Mac>::new_from_slice(&auth_key)
        .map_err(|_| PaserkError::CryptoError)?;
    tag_mac.update(header.as_bytes());
    tag_mac.update(c);
    tag_mac.update(edk);
    let computed_tag = tag_mac.finalize().into_bytes();

    let tag_valid: bool = computed_tag[..K1_SEAL_TAG_SIZE].ct_eq(tag).into();

    // Zeroize auth key before potentially returning error
    zeroize::Zeroize::zeroize(&mut auth_key);

    if !tag_valid {
        zeroize::Zeroize::zeroize(&mut r_bytes);
        return Err(PaserkError::AuthenticationFailed);
    }

    // Derive encryption key and counter: HMAC-SHA384(msg = 0x01 || h || r, key = SHA384(c))
    let mut ek_mac = <HmacSha384 as Mac>::new_from_slice(&c_hash)
        .map_err(|_| PaserkError::CryptoError)?;
    ek_mac.update(&[EK_DOMAIN_BYTE]);
    ek_mac.update(header.as_bytes());
    ek_mac.update(&r_bytes);
    let ek_result = ek_mac.finalize().into_bytes();

    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&ek_result[..32]);
    let mut counter = [0u8; 16];
    counter.copy_from_slice(&ek_result[32..48]);

    // Decrypt the encrypted data key with AES-256-CTR
    let mut plaintext = *edk;
    let mut cipher = Aes256Ctr::new(&encryption_key.into(), &counter.into());
    cipher.apply_keystream(&mut plaintext);

    // Zeroize sensitive data
    zeroize::Zeroize::zeroize(&mut r_bytes);
    zeroize::Zeroize::zeroize(&mut encryption_key);

    Ok(plaintext)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    /// Helper function to generate a 4096-bit RSA keypair for testing.
    #[cfg(feature = "k1-insecure")]
    fn generate_test_keypair() -> PaserkResult<(rsa::RsaPrivateKey, rsa::RsaPublicKey)> {
        use rsa::RsaPrivateKey;

        // Use a fixed seed for reproducible tests (still secure random for the key itself)
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 4096)
            .map_err(|_| PaserkError::CryptoError)?;
        let public_key = private_key.to_public_key();

        Ok((private_key, public_key))
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_seal_unseal_roundtrip() -> PaserkResult<()> {
        let (private_key, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k1.seal.";

        let (tag, edk, c) = seal_k1(&plaintext_key, &public_key, header)?;

        assert_ne!(edk, plaintext_key);

        let unsealed = unseal_k1(&tag, &edk, &c, &private_key, header)?;

        assert_eq!(unsealed, plaintext_key);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_seal_produces_different_output() -> PaserkResult<()> {
        let (_, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k1.seal.";

        let (tag1, edk1, c1) = seal_k1(&plaintext_key, &public_key, header)?;
        let (tag2, edk2, c2) = seal_k1(&plaintext_key, &public_key, header)?;

        // Different random r should produce different outputs
        assert_ne!(c1, c2);
        assert_ne!(edk1, edk2);
        assert_ne!(tag1, tag2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_unseal_wrong_key() -> PaserkResult<()> {
        let (_, public_key1) = generate_test_keypair()?;
        let (private_key2, _) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k1.seal.";

        let (tag, edk, c) = seal_k1(&plaintext_key, &public_key1, header)?;

        // Try to unseal with wrong key
        let result = unseal_k1(&tag, &edk, &c, &private_key2, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_unseal_modified_tag() -> PaserkResult<()> {
        let (private_key, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k1.seal.";

        let (mut tag, edk, c) = seal_k1(&plaintext_key, &public_key, header)?;

        tag[0] ^= 0xff;

        let result = unseal_k1(&tag, &edk, &c, &private_key, header);

        assert!(matches!(result, Err(PaserkError::AuthenticationFailed)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_rsa_ciphertext_size() -> PaserkResult<()> {
        let (_, public_key) = generate_test_keypair()?;

        let plaintext_key = [0x42u8; 32];
        let header = "k1.seal.";

        let (_, _, c) = seal_k1(&plaintext_key, &public_key, header)?;

        // 4096-bit RSA = 512 bytes
        assert_eq!(c.len(), 512);
        Ok(())
    }

    #[test]
    #[cfg(feature = "k1-insecure")]
    fn test_reject_wrong_key_size() -> PaserkResult<()> {
        use rsa::RsaPrivateKey;

        // Generate a 2048-bit key (wrong size)
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|_| PaserkError::CryptoError)?;
        let public_key = private_key.to_public_key();

        let plaintext_key = [0x42u8; 32];
        let header = "k1.seal.";

        let result = seal_k1(&plaintext_key, &public_key, header);

        assert!(matches!(result, Err(PaserkError::InvalidKey)));
        Ok(())
    }
}
