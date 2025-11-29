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
//! PASERK defines several key types:
//!
//! | Type | Format | Description |
//! |------|--------|-------------|
//! | `local` | `k{v}.local.{data}` | Symmetric encryption key |
//! | `public` | `k{v}.public.{data}` | Public verification key |
//! | `secret` | `k{v}.secret.{data}` | Secret signing key |
//! | `lid` | `k{v}.lid.{data}` | Local key identifier |
//! | `pid` | `k{v}.pid.{data}` | Public key identifier |
//! | `sid` | `k{v}.sid.{data}` | Secret key identifier |
//! | `local-wrap` | `k{v}.local-wrap.{protocol}.{data}` | Wrapped symmetric key |
//! | `secret-wrap` | `k{v}.secret-wrap.{protocol}.{data}` | Wrapped secret key |
//!
//! # Versions
//!
//! PASERK supports four versions, corresponding to PASETO versions:
//!
//! - **K1**: NIST Original (RSA + SHA-384)
//! - **K2**: Sodium Original (Ed25519 + BLAKE2b)
//! - **K3**: NIST Modern (P-384 + SHA-384)
//! - **K4**: Sodium Modern (Ed25519 + BLAKE2b) - **Recommended**
//!
//! # Features
//!
//! Enable specific versions with feature flags:
//!
//! ```toml
//! [dependencies]
//! paserk = { version = "0.1", features = ["k4"] }  # K4 only (default)
//! paserk = { version = "0.1", features = ["k2", "k4"] }  # K2 and K4
//! paserk = { version = "0.1", features = ["all-versions"] }  # All versions
//! ```
//!
//! # Security
//!
//! This crate follows security best practices:
//!
//! - Key material is zeroized on drop
//! - Debug output redacts sensitive key material
//! - Constant-time comparison for secret keys
//! - No unsafe code
//!
//! # Modules
//!
//! - [`core`] - Core types and operations
//! - [`prelude`] - Ergonomic imports (requires `prelude` feature)

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
