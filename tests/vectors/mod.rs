//! Test vector types for PASERK specification tests.
//!
//! These types are used to deserialize the official PASERK test vectors
//! from the paseto-standard/test-vectors repository.

// Many fields are required for deserialization but not directly used in tests
#![allow(dead_code)]

use serde::Deserialize;

/// A test vector suite (top-level JSON structure).
#[derive(Debug, Deserialize)]
pub struct TestVectorSuite<T> {
    pub name: String,
    pub tests: Vec<T>,
}

/// Common fields present in all test vectors.
#[derive(Debug, Deserialize)]
pub struct BaseTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
}

// =============================================================================
// Basic Key Types (local, public, secret)
// =============================================================================

/// Test vector for `local` type (symmetric key serialization).
#[derive(Debug, Deserialize)]
pub struct LocalTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded key bytes (null for fail tests)
    pub key: Option<String>,
    /// Expected PASERK string (null for fail tests)
    pub paserk: Option<String>,
}

/// Test vector for `public` type (public key serialization).
#[derive(Debug, Deserialize)]
pub struct PublicTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded public key bytes (null for fail tests)
    pub key: Option<String>,
    /// Expected PASERK string (null for fail tests)
    pub paserk: Option<String>,
}

/// Test vector for `secret` type (secret key serialization).
#[derive(Debug, Deserialize)]
pub struct SecretTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded secret key bytes (null for fail tests)
    pub key: Option<String>,
    /// Hex-encoded secret key seed (for Ed25519)
    #[serde(rename = "secret-key-seed")]
    pub secret_key_seed: Option<String>,
    /// Hex-encoded public key bytes
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    /// Expected PASERK string (null for fail tests)
    pub paserk: Option<String>,
}

// =============================================================================
// Key ID Types (lid, pid, sid)
// =============================================================================

/// Test vector for `lid` type (local key identifier).
#[derive(Debug, Deserialize)]
pub struct LidTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded key bytes
    pub key: Option<String>,
    /// Expected PASERK lid string
    pub paserk: Option<String>,
}

/// Test vector for `pid` type (public key identifier).
#[derive(Debug, Deserialize)]
pub struct PidTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded public key bytes
    pub key: Option<String>,
    /// Expected PASERK pid string
    pub paserk: Option<String>,
}

/// Test vector for `sid` type (secret key identifier).
#[derive(Debug, Deserialize)]
pub struct SidTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded secret key bytes
    pub key: Option<String>,
    /// Hex-encoded public key bytes (for deriving full key)
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    /// Expected PASERK sid string
    pub paserk: Option<String>,
}

// =============================================================================
// Key Wrapping Types (local-wrap, secret-wrap)
// =============================================================================

/// Test vector for `local-wrap.pie` type (PIE-wrapped symmetric key).
#[derive(Debug, Deserialize)]
pub struct LocalWrapTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded unwrapped key bytes
    pub unwrapped: Option<String>,
    /// Hex-encoded wrapping key bytes
    #[serde(rename = "wrapping-key")]
    pub wrapping_key: Option<String>,
    /// PASERK wrapped key string
    pub paserk: Option<String>,
}

/// Test vector for `secret-wrap.pie` type (PIE-wrapped secret key).
#[derive(Debug, Deserialize)]
pub struct SecretWrapTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded unwrapped secret key bytes
    pub unwrapped: Option<String>,
    /// Hex-encoded wrapping key bytes
    #[serde(rename = "wrapping-key")]
    pub wrapping_key: Option<String>,
    /// PASERK wrapped key string
    pub paserk: Option<String>,
}

// =============================================================================
// Password-Based Key Wrapping Types (local-pw, secret-pw)
// =============================================================================

/// Options for password-based key wrapping.
#[derive(Debug, Deserialize)]
pub struct PbkwOptions {
    /// Memory limit in bytes (Argon2)
    #[serde(default)]
    pub memlimit: Option<u32>,
    /// Operations/time limit (Argon2)
    #[serde(default)]
    pub opslimit: Option<u32>,
    /// Iterations (PBKDF2)
    #[serde(default)]
    pub iterations: Option<u32>,
}

/// Test vector for `local-pw` type (password-wrapped symmetric key).
#[derive(Debug, Deserialize)]
pub struct LocalPwTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded unwrapped key bytes
    pub unwrapped: Option<String>,
    /// Password (hex-encoded or raw string)
    pub password: Option<String>,
    /// PBKW options
    pub options: Option<PbkwOptions>,
    /// PASERK password-wrapped key string
    pub paserk: Option<String>,
}

/// Test vector for `secret-pw` type (password-wrapped secret key).
#[derive(Debug, Deserialize)]
pub struct SecretPwTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded unwrapped secret key bytes
    pub unwrapped: Option<String>,
    /// Password (hex-encoded or raw string)
    pub password: Option<String>,
    /// PBKW options
    pub options: Option<PbkwOptions>,
    /// PASERK password-wrapped key string
    pub paserk: Option<String>,
}

// =============================================================================
// Public Key Encryption Type (seal)
// =============================================================================

/// Test vector for `seal` type (PKE-encrypted symmetric key).
#[derive(Debug, Deserialize)]
pub struct SealTestVector {
    pub name: String,
    #[serde(rename = "expect-fail")]
    pub expect_fail: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Hex-encoded sealing secret key (Ed25519 or P-384 or RSA)
    #[serde(rename = "sealing-secret-key")]
    pub sealing_secret_key: Option<String>,
    /// Hex-encoded sealing public key
    #[serde(rename = "sealing-public-key")]
    pub sealing_public_key: Option<String>,
    /// Hex-encoded unsealed (plaintext) symmetric key
    pub unsealed: Option<String>,
    /// PASERK sealed key string
    pub paserk: Option<String>,
}

// =============================================================================
// Helper functions
// =============================================================================

/// Decode a hex string to bytes.
/// Returns `None` if the string is not valid hex.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Get password bytes from test vector.
/// The password field in test vectors should be used as-is without hex decoding.
/// Some test vectors have hex-encoded strings (e.g., "636f7272656374...") which
/// represent the literal ASCII characters, not decoded bytes.
pub fn decode_password(s: &str) -> Vec<u8> {
    // Use the password string directly as bytes
    s.as_bytes().to_vec()
}

/// Load a test vector suite from a JSON file.
pub fn load_vectors<T: serde::de::DeserializeOwned>(path: &str) -> TestVectorSuite<T> {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read test vector file {path}: {e}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse test vector file {path}: {e}"))
}
