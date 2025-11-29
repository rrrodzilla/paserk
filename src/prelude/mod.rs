//! Ergonomic layer for PASERK operations.
//!
//! The prelude module provides convenient re-exports of all PASERK types
//! and operations for easy importing.
//!
//! # Usage
//!
//! ```rust
//! use paserk::prelude::*;
//! ```
//!
//! # Available Types
//!
//! ## Key Types
//! - [`PaserkLocal`] - Symmetric encryption key
//! - [`PaserkPublic`] - Public verification key
//! - [`PaserkSecret`] - Secret signing key
//!
//! ## Key Identifiers
//! - [`PaserkLocalId`] - Local key identifier (lid)
//! - [`PaserkPublicId`] - Public key identifier (pid)
//! - [`PaserkSecretId`] - Secret key identifier (sid)
//!
//! ## Key Wrapping
//! - [`PaserkLocalWrap`] - PIE-wrapped symmetric key
//! - [`PaserkSecretWrap`] - PIE-wrapped secret key
//! - [`PaserkLocalPw`] - Password-wrapped symmetric key
//! - [`PaserkSecretPw`] - Password-wrapped secret key
//! - [`PaserkSeal`] - PKE-encrypted symmetric key
//!
//! ## Parameters
//! - [`Argon2Params`] - Argon2id parameters for password-based wrapping
//!   - Use `Argon2Params::interactive()` for fast operations
//!   - Use `Argon2Params::moderate()` for balanced security
//!   - Use `Argon2Params::sensitive()` for high-security operations
//!
//! # Future Enhancements
//!
//! Potential additions:
//! - Builder patterns for complex operations
//! - Additional convenience methods

// Re-export core types for convenience
pub use crate::core::error::{PaserkError, PaserkResult};
pub use crate::core::operations::wrap::{Pie, WrapProtocol};
pub use crate::core::types::{
    PaserkLocal, PaserkLocalId, PaserkLocalPw, PaserkLocalWrap, PaserkPublic, PaserkPublicId,
    PaserkSeal, PaserkSecret, PaserkSecretId, PaserkSecretPw, PaserkSecretWrap,
};
pub use crate::core::version::{K1, K2, K3, K4, PaserkVersion};

// Re-export PBKW parameters
#[cfg(any(feature = "k2", feature = "k4"))]
pub use crate::core::operations::pbkw::Argon2Params;
