//! Key ID computation operations.
//!
//! This module provides the ID hashing functions used to compute key identifiers
//! (lid, pid, sid) from PASERK keys.
//!
//! The hash algorithm depends on the PASERK version:
//! - K1/K3: SHA-384, truncated to 33 bytes (264 bits)
//! - K2/K4: `BLAKE2b` with 33-byte (264-bit) output

use crate::core::version::PaserkVersion;

/// ID hash output size (33 bytes = 264 bits).
pub const ID_HASH_SIZE: usize = 33;

/// Computes the PASERK ID hash.
///
/// The ID is computed by hashing the concatenation of the target header
/// and the full PASERK string representation of the key.
///
/// # Algorithm Selection
///
/// - K1/K3: SHA-384(header || `paserk_string`), truncated to 33 bytes
/// - K2/K4: `BLAKE2b`(header || `paserk_string`, 33 bytes)
///
/// # Arguments
///
/// * `header` - The target type header (e.g., "k4.lid.")
/// * `paserk_string` - The full PASERK string of the source key
///
/// # Returns
///
/// A 33-byte array containing the ID hash.
#[must_use]
pub fn compute_id<V: PaserkVersion>(header: &str, paserk_string: &str) -> [u8; ID_HASH_SIZE] {
    compute_id_for_version(V::VERSION, header, paserk_string)
}

/// Computes the ID hash for a specific version number.
///
/// This is the internal implementation that dispatches to the appropriate
/// algorithm based on the version number.
#[must_use]
fn compute_id_for_version(version: u8, header: &str, paserk_string: &str) -> [u8; ID_HASH_SIZE] {
    match version {
        #[cfg(any(feature = "k2", feature = "k4"))]
        2 | 4 => compute_id_blake2b(header, paserk_string),

        #[cfg(any(feature = "k1-insecure", feature = "k3"))]
        1 | 3 => compute_id_sha384(header, paserk_string),

        // This case handles versions that don't have their feature enabled
        _ => {
            // Return zeros for unsupported versions (should be caught at compile time)
            [0u8; ID_HASH_SIZE]
        }
    }
}

/// Computes the ID using `BLAKE2b` (for K2/K4).
#[cfg(any(feature = "k2", feature = "k4"))]
fn compute_id_blake2b(header: &str, paserk_string: &str) -> [u8; ID_HASH_SIZE] {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let Ok(mut hasher) = Blake2bVar::new(ID_HASH_SIZE) else {
        return [0u8; ID_HASH_SIZE]; // Should never happen with valid size
    };
    hasher.update(header.as_bytes());
    hasher.update(paserk_string.as_bytes());

    let mut output = [0u8; ID_HASH_SIZE];
    if hasher.finalize_variable(&mut output).is_err() {
        return [0u8; ID_HASH_SIZE]; // Should never happen
    }
    output
}

/// Computes the ID using SHA-384 (for K1/K3).
#[cfg(any(feature = "k1-insecure", feature = "k3"))]
fn compute_id_sha384(header: &str, paserk_string: &str) -> [u8; ID_HASH_SIZE] {
    use sha2::{Digest, Sha384};

    let mut hasher = Sha384::new();
    hasher.update(header.as_bytes());
    hasher.update(paserk_string.as_bytes());
    let result = hasher.finalize();

    // Truncate to 33 bytes (264 bits)
    let mut output = [0u8; ID_HASH_SIZE];
    output.copy_from_slice(&result[..ID_HASH_SIZE]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "k4")]
    fn test_compute_id_k4() {
        // Test that ID computation produces consistent, non-zero output
        let header = "k4.lid.";
        let paserk = "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8";

        let id = compute_id_for_version(4, header, paserk);

        // Should be 33 bytes
        assert_eq!(id.len(), ID_HASH_SIZE);

        // Should not be all zeros
        assert!(id.iter().any(|&b| b != 0));

        // Should be deterministic
        let id2 = compute_id_for_version(4, header, paserk);
        assert_eq!(id, id2);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_compute_id_different_inputs() {
        let header = "k4.lid.";
        let paserk1 = "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let paserk2 = "k4.local.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        let id1 = compute_id_for_version(4, header, paserk1);
        let id2 = compute_id_for_version(4, header, paserk2);

        // Different inputs should produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_compute_id_different_headers() {
        let paserk = "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8";

        let id_lid = compute_id_for_version(4, "k4.lid.", paserk);
        let id_other = compute_id_for_version(4, "k4.xxx.", paserk);

        // Different headers should produce different IDs
        assert_ne!(id_lid, id_other);
    }
}
