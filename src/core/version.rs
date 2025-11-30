//! PASERK version markers and traits.
//!
//! This module provides zero-sized type markers for each PASERK version (K1-K4)
//! and associated traits that determine which cryptographic algorithms are used
//! for each version.

use core::fmt::{self, Display};

mod private {
    pub trait Sealed {}
}

/// Trait for PASERK version markers.
///
/// This trait is sealed and cannot be implemented outside of this crate.
/// Each version marker (K1, K2, K3, K4) implements this trait with the
/// appropriate prefix string and version number.
pub trait PaserkVersion: private::Sealed + Default + Clone + Copy + Send + Sync + 'static {
    /// The version prefix (e.g., "k1", "k2", "k3", "k4")
    const PREFIX: &'static str;

    /// The numeric version (1, 2, 3, or 4)
    const VERSION: u8;
}

/// Marker trait for versions using `BLAKE2b` for ID computation (K2, K4).
pub trait UsesBlake2b: PaserkVersion {}

/// Marker trait for versions using SHA-384 for ID computation (K1, K3).
pub trait UsesSha384: PaserkVersion {}

/// Marker trait for versions using Argon2id for PBKW (K2, K4).
pub trait UsesArgon2: PaserkVersion {}

/// Marker trait for versions using PBKDF2 for PBKW (K1, K3).
pub trait UsesPbkdf2: PaserkVersion {}

/// Marker trait for versions using X25519 for PKE (K2, K4).
pub trait UsesX25519: PaserkVersion {}

/// Marker trait for versions using P-384 ECDH for PKE (K3).
pub trait UsesP384: PaserkVersion {}

/// Marker trait for versions using RSA-KEM for PKE (K1).
///
/// # Security Warning
///
/// **The `rsa` crate is vulnerable to [RUSTSEC-2023-0071] (Marvin Attack).**
/// Use [`K4`] with [`UsesX25519`] instead.
///
/// [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
#[deprecated(
    since = "0.1.0",
    note = "RSA is vulnerable to RUSTSEC-2023-0071 (Marvin Attack). Use K4 with X25519 instead."
)]
pub trait UsesRsa: PaserkVersion {}

/// Marker trait for versions using `XChaCha20` for encryption (K2, K4).
pub trait UsesXChaCha20: PaserkVersion {}

/// Marker trait for versions using AES-CTR for encryption (K1, K3).
pub trait UsesAesCtr: PaserkVersion {}

// =============================================================================
// Version 1: NIST Original
// =============================================================================

/// PASERK version K1 marker.
///
/// K1 corresponds to PASETO V1 and uses NIST algorithms:
/// - SHA-384 for ID computation
/// - PBKDF2-SHA384 for password-based key wrapping
/// - RSA-KEM for public key encryption
/// - AES-256-CTR + HMAC-SHA384 for symmetric operations
///
/// # Security Warning
///
/// **K1 uses the `rsa` crate which is vulnerable to [RUSTSEC-2023-0071] (Marvin Attack),
/// a timing side-channel attack that could enable private key recovery.**
///
/// Use [`K4`] for new projects. K1 is provided only for legacy PASETO V1 interoperability.
///
/// [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
#[deprecated(
    since = "0.1.0",
    note = "K1 uses RSA which is vulnerable to RUSTSEC-2023-0071 (Marvin Attack). Use K4 instead."
)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct K1;

#[allow(deprecated)]
impl private::Sealed for K1 {}

#[allow(deprecated)]
impl PaserkVersion for K1 {
    const PREFIX: &'static str = "k1";
    const VERSION: u8 = 1;
}

#[allow(deprecated)]
impl UsesSha384 for K1 {}
#[allow(deprecated)]
impl UsesPbkdf2 for K1 {}
#[allow(deprecated)]
impl UsesRsa for K1 {}
#[allow(deprecated)]
impl UsesAesCtr for K1 {}

#[allow(deprecated)]
impl Display for K1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::PREFIX)
    }
}

// =============================================================================
// Version 2: Sodium Original
// =============================================================================

/// PASERK version K2 marker.
///
/// K2 corresponds to PASETO V2 and uses Sodium/modern algorithms:
/// - BLAKE2b-264 for ID computation
/// - Argon2id for password-based key wrapping
/// - X25519 for public key encryption
/// - `XChaCha20` + `BLAKE2b` for symmetric operations
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct K2;

impl private::Sealed for K2 {}

impl PaserkVersion for K2 {
    const PREFIX: &'static str = "k2";
    const VERSION: u8 = 2;
}

impl UsesBlake2b for K2 {}
impl UsesArgon2 for K2 {}
impl UsesX25519 for K2 {}
impl UsesXChaCha20 for K2 {}

impl Display for K2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::PREFIX)
    }
}

// =============================================================================
// Version 3: NIST Modern
// =============================================================================

/// PASERK version K3 marker.
///
/// K3 corresponds to PASETO V3 and uses modern NIST algorithms:
/// - SHA-384 for ID computation
/// - PBKDF2-SHA384 for password-based key wrapping
/// - P-384 ECDH for public key encryption
/// - AES-256-CTR + HMAC-SHA384 for symmetric operations
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct K3;

impl private::Sealed for K3 {}

impl PaserkVersion for K3 {
    const PREFIX: &'static str = "k3";
    const VERSION: u8 = 3;
}

impl UsesSha384 for K3 {}
impl UsesPbkdf2 for K3 {}
impl UsesP384 for K3 {}
impl UsesAesCtr for K3 {}

impl Display for K3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::PREFIX)
    }
}

// =============================================================================
// Version 4: Sodium Modern (Recommended)
// =============================================================================

/// PASERK version K4 marker.
///
/// K4 corresponds to PASETO V4 and uses modern Sodium algorithms.
/// This is the recommended version for new applications.
///
/// - BLAKE2b-264 for ID computation
/// - Argon2id for password-based key wrapping
/// - X25519 for public key encryption
/// - `XChaCha20` + `BLAKE2b` for symmetric operations
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct K4;

impl private::Sealed for K4 {}

impl PaserkVersion for K4 {
    const PREFIX: &'static str = "k4";
    const VERSION: u8 = 4;
}

impl UsesBlake2b for K4 {}
impl UsesArgon2 for K4 {}
impl UsesX25519 for K4 {}
impl UsesXChaCha20 for K4 {}

impl Display for K4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::PREFIX)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_version_prefixes() {
        assert_eq!(K1::PREFIX, "k1");
        assert_eq!(K2::PREFIX, "k2");
        assert_eq!(K3::PREFIX, "k3");
        assert_eq!(K4::PREFIX, "k4");
    }

    #[test]
    fn test_version_numbers() {
        assert_eq!(K1::VERSION, 1);
        assert_eq!(K2::VERSION, 2);
        assert_eq!(K3::VERSION, 3);
        assert_eq!(K4::VERSION, 4);
    }

    #[test]
    fn test_display() {
        assert_eq!(K1.to_string(), "k1");
        assert_eq!(K2.to_string(), "k2");
        assert_eq!(K3.to_string(), "k3");
        assert_eq!(K4.to_string(), "k4");
    }

    #[test]
    fn test_default() {
        let k1: K1 = K1;
        let k2: K2 = K2;
        let k3: K3 = K3;
        let k4: K4 = K4;
        assert_eq!(k1, K1);
        assert_eq!(k2, K2);
        assert_eq!(k3, K3);
        assert_eq!(k4, K4);
    }

    #[test]
    fn test_copy_clone() {
        let k4 = K4;
        let k4_clone = k4;
        let k4_copy = k4;
        assert_eq!(k4_clone, K4);
        assert_eq!(k4_copy, K4);
    }
}
