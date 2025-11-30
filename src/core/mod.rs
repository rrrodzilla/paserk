//! Core PASERK types and operations.
//!
//! This module provides the fundamental building blocks for PASERK:
//!
//! - [`version`] - Version markers (K1, K2, K3, K4) and associated traits
//! - [`error`] - Error types for PASERK operations
//! - [`header`] - Header parsing and generation utilities
//! - [`types`] - First-class PASERK types (local, public, secret, IDs, etc.)
//! - [`operations`] - Cryptographic operations (ID computation, wrapping, etc.)

pub mod error;
pub mod header;
pub mod operations;
pub mod types;
pub mod version;

// Re-export commonly used items
pub use error::{PaserkError, PaserkResult};
#[allow(deprecated)]
pub use version::{PaserkVersion, K1, K2, K3, K4};
