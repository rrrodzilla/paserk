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
pub use crate::core::types::{
    PaserkLocal, PaserkLocalId, PaserkPublic, PaserkPublicId, PaserkSecret, PaserkSecretId,
};
pub use crate::core::version::{K1, K2, K3, K4, PaserkVersion};
