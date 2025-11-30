//! Platform-Agnostic Serialized Keys (PASERK) for PASETO.
//!
//! PASERK is a standard format for serializing keys used with PASETO tokens.
//! This crate provides a type-safe, idiomatic Rust implementation of the
//! PASERK specification.
//!
//! # Quick Start
//!
//! ```rust
//! use paserk::core::types::PaserkLocal;
//! use paserk::core::version::K4;
//!
//! // Create a PASERK key from raw bytes
//! let key_bytes: [u8; 32] = [0u8; 32];
//! let paserk_key = PaserkLocal::<K4>::from(key_bytes);
//!
//! // Serialize to PASERK string format
//! let paserk_string = paserk_key.to_string();
//! assert!(paserk_string.starts_with("k4.local."));
//!
//! // Parse a PASERK string back to a key
//! let parsed = PaserkLocal::<K4>::try_from(paserk_string.as_str());
//! assert!(parsed.is_ok());
//! ```
//!
//! # PASERK Types
//!
//! All PASERK key types are implemented for K2/K4 (Sodium) versions:
//!
//! | Type | Format | Description | Status |
//! |------|--------|-------------|--------|
//! | `local` | `k{v}.local.{data}` | Symmetric encryption key | ✅ K2/K4 |
//! | `public` | `k{v}.public.{data}` | Public verification key | ✅ K2/K4 |
//! | `secret` | `k{v}.secret.{data}` | Secret signing key | ✅ K2/K4 |
//! | `lid` | `k{v}.lid.{data}` | Local key identifier | ✅ K2/K4 |
//! | `pid` | `k{v}.pid.{data}` | Public key identifier | ✅ K2/K4 |
//! | `sid` | `k{v}.sid.{data}` | Secret key identifier | ✅ K2/K4 |
//! | `local-wrap` | `k{v}.local-wrap.pie.{data}` | PIE-wrapped symmetric key | ✅ K2/K4 |
//! | `secret-wrap` | `k{v}.secret-wrap.pie.{data}` | PIE-wrapped secret key | ✅ K2/K4 |
//! | `local-pw` | `k{v}.local-pw.{data}` | Password-wrapped symmetric key | ✅ K2/K4 |
//! | `secret-pw` | `k{v}.secret-pw.{data}` | Password-wrapped secret key | ✅ K2/K4 |
//! | `seal` | `k{v}.seal.{data}` | PKE-encrypted symmetric key | ✅ K2/K4 |
//!
//! # Versions
//!
//! PASERK supports four versions, corresponding to PASETO versions:
//!
//! | Version | Algorithms | Status |
//! |---------|------------|--------|
//! | **K1** | RSA + AES-CTR + HMAC-SHA384 | ⏳ Not yet implemented |
//! | **K2** | Ed25519 + XChaCha20 + BLAKE2b | ✅ Fully implemented |
//! | **K3** | P-384 + AES-CTR + HMAC-SHA384 | ⏳ Not yet implemented |
//! | **K4** | Ed25519 + XChaCha20 + BLAKE2b | ✅ Fully implemented (Recommended) |
//!
//! # Features
//!
//! Enable specific versions with feature flags:
//!
//! ```toml
//! [dependencies]
//! paserk = { version = "0.1", features = ["k4"] }  # K4 only (default, recommended)
//! paserk = { version = "0.1", features = ["k2", "k4"] }  # K2 and K4
//! ```
//!
//! **Note:** K1 and K3 features are defined but not yet implemented. Using them
//! will compile but operations will not be available until implementation is complete.
//!
//! # Cryptographic Operations
//!
//! ## Key Wrapping (PIE Protocol)
//! - XChaCha20 for encryption
//! - BLAKE2b for key derivation and authentication
//!
//! ## Password-Based Key Wrapping (PBKW)
//! - Argon2id for key derivation with configurable parameters
//! - XChaCha20 for encryption
//! - BLAKE2b for authentication
//!
//! ## Public Key Encryption (Seal)
//! - X25519 ECDH for key exchange
//! - BLAKE2b for key derivation
//! - XChaCha20 for encryption
//!
//! # Security
//!
//! This crate follows security best practices:
//!
//! - Key material is zeroized on drop
//! - Debug output redacts sensitive key material
//! - Constant-time comparison for secret keys
//! - No unsafe code (`#![forbid(unsafe_code)]`)
//! - Authenticated encryption prevents tampering
//!
//! # Modules
//!
//! - [`core`] - Core types and operations
//! - [`prelude`] - Ergonomic imports (requires `prelude` feature)
//!
//! # Builder Patterns
//!
//! The `prelude` module provides fluent builder APIs for password-based wrapping:
//!
//! ```rust
//! use paserk::prelude::*;
//!
//! let key = PaserkLocal::<K4>::from([0x42u8; 32]);
//!
//! // Use preset security profiles
//! let wrapped = LocalPwBuilder::<K4>::moderate()
//!     .try_wrap(&key, b"password")
//!     .expect("wrap should succeed");
//!
//! // Or customize parameters
//! let wrapped = LocalPwBuilder::<K4>::new()
//!     .memory_kib(128 * 1024)
//!     .iterations(3)
//!     .parallelism(2)
//!     .try_wrap(&key, b"password")
//!     .expect("wrap should succeed");
//! ```

pub mod core;

#[cfg(feature = "prelude")]
pub mod prelude;

// Re-export commonly used items at crate root
pub use core::error::{PaserkError, PaserkResult};
pub use core::version::{K1, K2, K3, K4, PaserkVersion};

// Re-export types based on enabled version features
#[cfg(feature = "k4")]
pub use core::types::{
    PaserkLocal, PaserkLocalId, PaserkLocalPw, PaserkLocalWrap, PaserkPublic, PaserkPublicId,
    PaserkSeal, PaserkSecret, PaserkSecretId, PaserkSecretPw, PaserkSecretWrap,
};

// Re-export wrap protocol markers
pub use core::operations::wrap::{Pie, WrapProtocol};

// Re-export PBKW parameters
#[cfg(any(feature = "k2", feature = "k4"))]
pub use core::operations::pbkw::Argon2Params;

// Version-specific type aliases for when only one version is enabled
#[cfg(all(feature = "k4", not(any(feature = "k1", feature = "k2", feature = "k3"))))]
pub mod types {
    //! Convenient type aliases for K4 (default version).

    use super::core::operations::wrap::Pie;
    use super::core::types;
    use super::K4;

    /// Symmetric key for K4.
    pub type LocalKey = types::PaserkLocal<K4>;
    /// Public key for K4.
    pub type PublicKey = types::PaserkPublic<K4>;
    /// Secret key for K4.
    pub type SecretKey = types::PaserkSecret<K4>;
    /// Local key ID for K4.
    pub type LocalKeyId = types::PaserkLocalId<K4>;
    /// Public key ID for K4.
    pub type PublicKeyId = types::PaserkPublicId<K4>;
    /// Secret key ID for K4.
    pub type SecretKeyId = types::PaserkSecretId<K4>;
    /// Wrapped local key for K4.
    pub type LocalKeyWrap = types::PaserkLocalWrap<K4, Pie>;
    /// Wrapped secret key for K4.
    pub type SecretKeyWrap = types::PaserkSecretWrap<K4, Pie>;
    /// Password-wrapped local key for K4.
    pub type LocalKeyPw = types::PaserkLocalPw<K4>;
    /// Password-wrapped secret key for K4.
    pub type SecretKeyPw = types::PaserkSecretPw<K4>;
    /// Sealed (PKE-encrypted) local key for K4.
    pub type SealedKey = types::PaserkSeal<K4>;
}
