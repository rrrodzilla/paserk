//! Build script for paserk.
//!
//! This emits compile-time warnings for security-sensitive feature flags.

fn main() {
    // Emit a compile-time warning when k1-insecure feature is enabled
    #[cfg(feature = "k1-insecure")]
    {
        // Note: Using single-colon syntax for MSRV 1.75.0 compatibility
        println!("cargo:warning=SECURITY WARNING: The 'k1-insecure' feature is enabled.");
        println!("cargo:warning=K1 uses the `rsa` crate which is vulnerable to RUSTSEC-2023-0071 (Marvin Attack).");
        println!("cargo:warning=This timing side-channel attack could enable private key recovery.");
        println!("cargo:warning=Use K4 for new projects. K1 is provided only for legacy PASETO V1 interoperability.");
    }
}
