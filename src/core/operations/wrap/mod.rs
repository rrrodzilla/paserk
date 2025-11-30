//! Key wrapping operations.
//!
//! This module provides symmetric key wrapping using the PIE protocol.
//! Key wrapping allows a symmetric key to be encrypted with another
//! symmetric key for secure storage or transmission.
//!
//! Types:
//! - `local-wrap.pie` - Symmetric key wrapped with symmetric key
//! - `secret-wrap.pie` - Secret key wrapped with symmetric key
//!
//! # PIE Protocol
//!
//! PIE (Platform-Independent Encryption) is the standard key wrapping
//! protocol for PASERK. It provides authenticated encryption:
//!
//! - For K2/K4: Uses XChaCha20 for encryption and BLAKE2b for authentication (32-byte tag)
//! - For K1/K3: Uses AES-256-CTR for encryption and HMAC-SHA384 for authentication (48-byte tag)
//!
//! # Example
//!
//! ```rust
//! use paserk::core::types::{PaserkLocal, PaserkLocalWrap};
//! use paserk::core::operations::wrap::Pie;
//! use paserk::core::version::K4;
//!
//! // Create keys
//! let wrapping_key = PaserkLocal::<K4>::from([0x42u8; 32]);
//! let key_to_wrap = PaserkLocal::<K4>::from([0x13u8; 32]);
//!
//! // Wrap the key
//! let wrapped = PaserkLocalWrap::<K4, Pie>::try_wrap(&key_to_wrap, &wrapping_key)
//!     .expect("wrap should succeed");
//!
//! // Serialize to PASERK string
//! let paserk_string = wrapped.to_string();
//! assert!(paserk_string.starts_with("k4.local-wrap.pie."));
//!
//! // Parse and unwrap
//! let parsed = PaserkLocalWrap::<K4, Pie>::try_from(paserk_string.as_str())
//!     .expect("parse should succeed");
//! let unwrapped = parsed.try_unwrap(&wrapping_key)
//!     .expect("unwrap should succeed");
//!
//! assert_eq!(unwrapped.as_bytes(), key_to_wrap.as_bytes());
//! ```

mod pie;
mod protocol;

pub use pie::{PIE_NONCE_SIZE, PIE_TAG_SIZE};
pub use protocol::{Pie, WrapProtocol};

// K1/K3 PIE constants and functions (use different tag size - 48 bytes for HMAC-SHA384)
#[cfg(any(feature = "k1", feature = "k3"))]
pub use pie::{PIE_K1K3_NONCE_SIZE, PIE_K1K3_TAG_SIZE};

// Re-export internal functions for use by types module
#[cfg(any(feature = "k2", feature = "k4"))]
pub(crate) use pie::{
    pie_unwrap_local_k2k4, pie_unwrap_secret_k2k4, pie_wrap_local_k2k4, pie_wrap_secret_k2k4,
};

#[cfg(any(feature = "k1", feature = "k3"))]
pub(crate) use pie::{pie_unwrap_local_k1k3, pie_wrap_local_k1k3};

#[cfg(feature = "k3")]
pub(crate) use pie::{pie_unwrap_secret_k3, pie_wrap_secret_k3};
