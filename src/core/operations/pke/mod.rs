//! Public key encryption (PKE) operations.
//!
//! This module provides public key encryption for symmetric keys using
//! X25519 (K2/K4). K1/K3 support is planned for future releases.
//!
//! Types:
//! - `seal` - Symmetric key encrypted with public key
//!
//! # Security
//!
//! PKE allows a symmetric key to be encrypted using a recipient's public key,
//! so that only the holder of the corresponding secret key can decrypt it.
//!
//! # Example
//!
//! ```rust,ignore
//! use paserk::core::types::{PaserkLocal, PaserkSecret, PaserkSeal};
//! use paserk::core::version::K4;
//! use ed25519_dalek::SigningKey;
//!
//! // Create Ed25519 keypair from seed bytes
//! let seed = [0u8; 32]; // Use secure random bytes in production!
//! let signing_key = SigningKey::from_bytes(&seed);
//! let secret_key = PaserkSecret::<K4>::from(signing_key.to_keypair_bytes());
//!
//! // Create a symmetric key to seal
//! let local_key = PaserkLocal::<K4>::from([0x42u8; 32]);
//!
//! // Seal with the secret key's corresponding public key
//! let sealed = PaserkSeal::<K4>::try_seal(&local_key, &secret_key)?;
//!
//! // Serialize
//! let paserk_string = sealed.to_string();
//!
//! // Parse and unseal
//! let parsed = PaserkSeal::<K4>::try_from(paserk_string.as_str())?;
//! let unsealed = parsed.try_unseal(&secret_key)?;
//! # Ok::<(), paserk::PaserkError>(())
//! ```

#[cfg(any(feature = "k2", feature = "k4"))]
mod seal_k2k4;

#[cfg(any(feature = "k2", feature = "k4"))]
pub use seal_k2k4::{EPHEMERAL_PK_SIZE, SEAL_CIPHERTEXT_SIZE, SEAL_DATA_SIZE, SEAL_TAG_SIZE};

#[cfg(any(feature = "k2", feature = "k4"))]
pub(crate) use seal_k2k4::{seal_k2k4, unseal_k2k4};
