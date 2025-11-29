//! Cryptographic operations for PASERK.
//!
//! This module provides the cryptographic operations used by PASERK:
//!
//! - [`id`] - Key ID computation (hashing)
//! - [`wrap`] - Key wrapping operations (PIE protocol)
//! - [`pbkw`] - Password-based key wrapping (Argon2/PBKDF2)
//! - [`pke`] - Public key encryption (seal/unseal)

pub mod id;

// These modules will be implemented in later phases
pub mod pbkw;
pub mod pke;
pub mod wrap;
