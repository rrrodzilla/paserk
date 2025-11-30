//! Password-based key wrapping (PBKW).
//!
//! This module provides password-based key wrapping using Argon2id (K2/K4)
//! or PBKDF2-SHA384 (K1/K3).
//!
//! Types:
//! - `local-pw` - Symmetric key wrapped with password
//! - `secret-pw` - Secret key wrapped with password
//!
//! # Security
//!
//! PBKW allows keys to be encrypted using a user-provided password. The
//! password is stretched using a memory-hard key derivation function
//! (Argon2id for K2/K4) to resist brute-force attacks.
//!
//! # Parameter Selection
//!
//! Choose parameters based on your security requirements:
//!
//! ## K2/K4 (Argon2id)
//! - **Interactive**: Fast enough for user logins (64 MiB, 2 iterations)
//! - **Moderate**: Balanced for most applications (256 MiB, 3 iterations)
//! - **Sensitive**: High security for long-term storage (1 GiB, 4 iterations)
//!
//! ## K1/K3 (PBKDF2-SHA384)
//! - **Interactive**: 100,000 iterations
//! - **Moderate**: 310,000 iterations (OWASP 2023 recommendation)
//! - **Sensitive**: 600,000 iterations
//!
//! # Example
//!
//! ```rust
//! use paserk::core::types::{PaserkLocal, PaserkLocalPw};
//! use paserk::core::operations::pbkw::Argon2Params;
//! use paserk::core::version::K4;
//!
//! // Create a key to wrap
//! let key = PaserkLocal::<K4>::from([0x42u8; 32]);
//!
//! // Wrap with password using moderate security
//! let wrapped = PaserkLocalPw::<K4>::try_wrap(&key, b"my-password", Argon2Params::moderate())
//!     .expect("wrap should succeed");
//!
//! // Serialize to PASERK string (safe to store)
//! let paserk_string = wrapped.to_string();
//! assert!(paserk_string.starts_with("k4.local-pw."));
//!
//! // Parse and unwrap
//! let parsed = PaserkLocalPw::<K4>::try_from(paserk_string.as_str())
//!     .expect("parse should succeed");
//! let unwrapped = parsed.try_unwrap(b"my-password", Argon2Params::moderate())
//!     .expect("unwrap should succeed");
//!
//! assert_eq!(unwrapped.as_bytes(), key.as_bytes());
//! ```

#[cfg(any(feature = "k2", feature = "k4"))]
mod argon2_impl;

#[cfg(any(feature = "k1-insecure", feature = "k3"))]
mod pbkdf2_impl;

#[cfg(any(feature = "k2", feature = "k4"))]
pub use argon2_impl::{Argon2Params, ARGON2_SALT_SIZE, PBKW_TAG_SIZE, XCHACHA20_NONCE_SIZE};

#[cfg(any(feature = "k2", feature = "k4"))]
pub(crate) use argon2_impl::{
    pbkw_unwrap_local_k2k4, pbkw_unwrap_secret_k2k4, pbkw_wrap_local_k2k4, pbkw_wrap_secret_k2k4,
};

#[cfg(any(feature = "k1-insecure", feature = "k3"))]
pub use pbkdf2_impl::{
    Pbkdf2Params, AES_CTR_NONCE_SIZE, PBKDF2_SALT_SIZE, PBKW_K1K3_TAG_SIZE,
};

#[cfg(any(feature = "k1-insecure", feature = "k3"))]
pub(crate) use pbkdf2_impl::{pbkw_unwrap_local_k1k3, pbkw_wrap_local_k1k3};

#[cfg(feature = "k3")]
pub(crate) use pbkdf2_impl::{pbkw_unwrap_secret_k3, pbkw_wrap_secret_k3};
