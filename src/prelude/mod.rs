//! Ergonomic layer for PASERK operations.
//!
//! The prelude module provides convenient type aliases, builder patterns,
//! and parameter presets for common PASERK operations.
//!
//! # Usage
//!
//! ```rust
//! use paserk::prelude::*;
//! ```
//!
//! # Future Implementation
//!
//! This module will be expanded in Phase 7 to include:
//! - Builder patterns for PBKW operations
//! - Preset parameter profiles (interactive, moderate, sensitive)
//! - Convenient type aliases

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
