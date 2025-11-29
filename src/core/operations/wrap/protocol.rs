//! Wrap protocol definitions and marker types.
//!
//! This module defines the `WrapProtocol` trait and marker types for
//! different key wrapping protocols supported by PASERK.

mod private {
    pub trait Sealed {}
}

/// Trait for wrap protocol markers.
///
/// This trait is sealed and cannot be implemented outside of this crate.
/// Protocol markers determine which encryption algorithm is used for
/// key wrapping operations.
pub trait WrapProtocol: private::Sealed + Default + Clone + Copy + Send + Sync + 'static {
    /// The protocol identifier (e.g., "pie")
    const PROTOCOL_ID: &'static str;
}

/// Platform-Independent Encryption (PIE) protocol marker.
///
/// PIE is the standard key wrapping protocol for PASERK.
/// - For K2/K4: Uses XChaCha20 + BLAKE2b
/// - For K1/K3: Uses AES-256-CTR + HMAC-SHA384
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pie;

impl private::Sealed for Pie {}

impl WrapProtocol for Pie {
    const PROTOCOL_ID: &'static str = "pie";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pie_protocol_id() {
        assert_eq!(Pie::PROTOCOL_ID, "pie");
    }

    #[test]
    fn test_pie_default() {
        let _pie: Pie = Pie::default();
    }

    #[test]
    fn test_pie_clone_copy() {
        let pie = Pie;
        let pie_clone = pie;
        let _pie_copy = pie;
        assert_eq!(pie_clone, Pie);
    }
}
