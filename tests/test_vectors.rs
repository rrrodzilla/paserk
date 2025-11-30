//! Integration tests using official PASERK test vectors.
//!
//! These tests use the test vectors from the paseto-standard/test-vectors
//! repository to verify compliance with the PASERK specification.

// Test code legitimately uses panic patterns for test failure reporting
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
mod vectors;

#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
use std::path::PathBuf;
#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
use vectors::*;

/// Get the path to the test vectors directory.
#[cfg(any(
    feature = "k1-insecure",
    feature = "k2",
    feature = "k3",
    feature = "k4"
))]
fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

// =============================================================================
// K4 Test Vectors
// =============================================================================

#[cfg(feature = "k4")]
mod k4_tests {
    use super::*;
    use paserk::core::operations::wrap::Pie;
    use paserk::core::types::{
        PaserkLocal, PaserkLocalId, PaserkLocalPw, PaserkLocalWrap, PaserkPublic, PaserkPublicId,
        PaserkSeal, PaserkSecret, PaserkSecretId, PaserkSecretPw, PaserkSecretWrap,
    };
    use paserk::K4;

    #[test]
    fn test_k4_local_vectors() {
        let path = vectors_dir().join("k4.local.json");
        let suite: TestVectorSuite<LocalTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // Test should fail to parse
                if let Some(paserk) = &test.paserk {
                    let result = PaserkLocal::<K4>::try_from(paserk.as_str());
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed but succeeded",
                        test.name
                    );
                }
            } else {
                // Test should succeed
                let key_bytes =
                    hex_decode(test.key.as_ref().expect("key required for success test"))
                        .expect("valid hex");
                let paserk_str = test
                    .paserk
                    .as_ref()
                    .expect("paserk required for success test");

                // Test serialization
                let key_array: [u8; 32] = key_bytes.try_into().expect("key should be 32 bytes");
                let paserk = PaserkLocal::<K4>::from(key_array);
                assert_eq!(
                    paserk.to_string(),
                    *paserk_str,
                    "Test '{}' serialization failed",
                    test.name
                );

                // Test parsing
                let parsed = PaserkLocal::<K4>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                assert_eq!(
                    parsed.as_bytes(),
                    &key_array,
                    "Test '{}' roundtrip failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_lid_vectors() {
        let path = vectors_dir().join("k4.lid.json");
        let suite: TestVectorSuite<LidTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // For lid, expect-fail typically means the key is invalid
                // We can't really test this since PaserkLocalId is derived from a valid key
                continue;
            }

            let key_bytes = hex_decode(test.key.as_ref().expect("key required for success test"))
                .expect("valid hex");
            let paserk_str = test
                .paserk
                .as_ref()
                .expect("paserk required for success test");

            let key_array: [u8; 32] = key_bytes.try_into().expect("key should be 32 bytes");
            let local_key = PaserkLocal::<K4>::from(key_array);
            let lid: PaserkLocalId<K4> = (&local_key).into();

            assert_eq!(
                lid.to_string(),
                *paserk_str,
                "Test '{}' lid computation failed",
                test.name
            );
        }
    }

    #[test]
    fn test_k4_public_vectors() {
        let path = vectors_dir().join("k4.public.json");
        let suite: TestVectorSuite<PublicTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                if let Some(paserk) = &test.paserk {
                    let result = PaserkPublic::<K4>::try_from(paserk.as_str());
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed but succeeded",
                        test.name
                    );
                }
            } else {
                let key_bytes =
                    hex_decode(test.key.as_ref().expect("key required for success test"))
                        .expect("valid hex");
                let paserk_str = test
                    .paserk
                    .as_ref()
                    .expect("paserk required for success test");

                let key_array: [u8; 32] = key_bytes.try_into().expect("key should be 32 bytes");
                let paserk = PaserkPublic::<K4>::from(key_array);

                assert_eq!(
                    paserk.to_string(),
                    *paserk_str,
                    "Test '{}' serialization failed",
                    test.name
                );

                let parsed = PaserkPublic::<K4>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                assert_eq!(
                    parsed.as_bytes(),
                    &key_array,
                    "Test '{}' roundtrip failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_pid_vectors() {
        let path = vectors_dir().join("k4.pid.json");
        let suite: TestVectorSuite<PidTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                continue;
            }

            let key_bytes = hex_decode(test.key.as_ref().expect("key required for success test"))
                .expect("valid hex");
            let paserk_str = test
                .paserk
                .as_ref()
                .expect("paserk required for success test");

            let key_array: [u8; 32] = key_bytes.try_into().expect("key should be 32 bytes");
            let public_key = PaserkPublic::<K4>::from(key_array);
            let pid: PaserkPublicId<K4> = (&public_key).into();

            assert_eq!(
                pid.to_string(),
                *paserk_str,
                "Test '{}' pid computation failed",
                test.name
            );
        }
    }

    #[test]
    fn test_k4_secret_vectors() {
        let path = vectors_dir().join("k4.secret.json");
        let suite: TestVectorSuite<SecretTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                if let Some(paserk) = &test.paserk {
                    let result = PaserkSecret::<K4>::try_from(paserk.as_str());
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed but succeeded",
                        test.name
                    );
                }
            } else {
                let key_bytes =
                    hex_decode(test.key.as_ref().expect("key required for success test"))
                        .expect("valid hex");
                let paserk_str = test
                    .paserk
                    .as_ref()
                    .expect("paserk required for success test");

                let key_array: [u8; 64] = key_bytes.try_into().expect("key should be 64 bytes");
                let paserk = PaserkSecret::<K4>::from(key_array);

                assert_eq!(
                    paserk.to_string(),
                    *paserk_str,
                    "Test '{}' serialization failed",
                    test.name
                );

                let parsed = PaserkSecret::<K4>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                assert_eq!(
                    parsed.as_bytes(),
                    &key_array,
                    "Test '{}' roundtrip failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_sid_vectors() {
        let path = vectors_dir().join("k4.sid.json");
        let suite: TestVectorSuite<SidTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                continue;
            }

            let key_bytes = hex_decode(test.key.as_ref().expect("key required for success test"))
                .expect("valid hex");
            let paserk_str = test
                .paserk
                .as_ref()
                .expect("paserk required for success test");

            let key_array: [u8; 64] = key_bytes.try_into().expect("key should be 64 bytes");
            let secret_key = PaserkSecret::<K4>::from(key_array);
            let sid: PaserkSecretId<K4> = (&secret_key).into();

            assert_eq!(
                sid.to_string(),
                *paserk_str,
                "Test '{}' sid computation failed",
                test.name
            );
        }
    }

    #[test]
    fn test_k4_local_wrap_pie_vectors() {
        let path = vectors_dir().join("k4.local-wrap.pie.json");
        let suite: TestVectorSuite<LocalWrapTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // Test unwrapping should fail
                let paserk_str = test.paserk.as_ref().expect("paserk required for fail test");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let wrapping_key: [u8; 32] = wrapping_key_bytes
                    .try_into()
                    .expect("wrapping key should be 32 bytes");
                let wrapping_key = PaserkLocal::<K4>::from(wrapping_key);

                let wrapped = PaserkLocalWrap::<K4, Pie>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    let result = wrapped.try_unwrap(&wrapping_key);
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed to unwrap",
                        test.name
                    );
                }
            } else {
                // Test wrapping roundtrip
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped key required"))
                        .expect("valid hex");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 32] = unwrapped_bytes
                    .try_into()
                    .expect("unwrapped key should be 32 bytes");
                let wrapping_key: [u8; 32] = wrapping_key_bytes
                    .try_into()
                    .expect("wrapping key should be 32 bytes");

                let key_to_wrap = PaserkLocal::<K4>::from(unwrapped_key);
                let wrapping_key = PaserkLocal::<K4>::from(wrapping_key);

                // Parse the wrapped key and unwrap it
                let wrapped = PaserkLocalWrap::<K4, Pie>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&wrapping_key)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    key_to_wrap.as_bytes(),
                    "Test '{}' unwrap produced wrong key",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_secret_wrap_pie_vectors() {
        let path = vectors_dir().join("k4.secret-wrap.pie.json");
        let suite: TestVectorSuite<SecretWrapTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                let paserk_str = test.paserk.as_ref().expect("paserk required for fail test");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let wrapping_key: [u8; 32] = wrapping_key_bytes
                    .try_into()
                    .expect("wrapping key should be 32 bytes");
                let wrapping_key = PaserkLocal::<K4>::from(wrapping_key);

                let wrapped = PaserkSecretWrap::<K4, Pie>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    let result = wrapped.try_unwrap(&wrapping_key);
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed to unwrap",
                        test.name
                    );
                }
            } else {
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped key required"))
                        .expect("valid hex");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 64] = unwrapped_bytes
                    .try_into()
                    .expect("unwrapped key should be 64 bytes");
                let wrapping_key: [u8; 32] = wrapping_key_bytes
                    .try_into()
                    .expect("wrapping key should be 32 bytes");

                let key_to_wrap = PaserkSecret::<K4>::from(unwrapped_key);
                let wrapping_key = PaserkLocal::<K4>::from(wrapping_key);

                let wrapped = PaserkSecretWrap::<K4, Pie>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&wrapping_key)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    key_to_wrap.as_bytes(),
                    "Test '{}' unwrap produced wrong key",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_local_pw_vectors() {
        use paserk::Argon2Params;

        let path = vectors_dir().join("k4.local-pw.json");
        let suite: TestVectorSuite<LocalPwTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // For fail tests, the paserk might be for a wrong version (e.g., k3 instead of k4)
                // In that case, parsing should fail, so we don't need params
                let paserk_str = test.paserk.as_ref().expect("paserk required for fail test");
                let password = decode_password(test.password.as_ref().expect("password required"));

                let wrapped = PaserkLocalPw::<K4>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    // Only try to unwrap if parsing succeeded
                    // Extract params if available, otherwise use defaults (will likely fail)
                    let options = test.options.as_ref();
                    let params = Argon2Params {
                        memory_kib: options.and_then(|o| o.memlimit).map_or(65536, |m| m / 1024),
                        iterations: options.and_then(|o| o.opslimit).unwrap_or(2),
                        parallelism: 1,
                    };
                    let result = wrapped.try_unwrap(&password, params);
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed to unwrap",
                        test.name
                    );
                }
                // If parsing failed, that's also an expected failure - test passes
            } else {
                // Extract Argon2 parameters from test options
                let options = test.options.as_ref().expect("options required");
                let params = Argon2Params {
                    memory_kib: options.memlimit.expect("memlimit required") / 1024, // bytes to KiB
                    iterations: options.opslimit.expect("opslimit required"),
                    parallelism: 1,
                };
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped key required"))
                        .expect("valid hex");
                let password = decode_password(test.password.as_ref().expect("password required"));
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 32] = unwrapped_bytes
                    .try_into()
                    .expect("unwrapped key should be 32 bytes");
                let expected_key = PaserkLocal::<K4>::from(unwrapped_key);

                let wrapped = PaserkLocalPw::<K4>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&password, params)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    expected_key.as_bytes(),
                    "Test '{}' unwrap produced wrong key",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_secret_pw_vectors() {
        use paserk::Argon2Params;

        let path = vectors_dir().join("k4.secret-pw.json");
        let suite: TestVectorSuite<SecretPwTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // For fail tests, the paserk might be for a wrong version (e.g., k3 instead of k4)
                // In that case, parsing should fail, so we don't need params
                let paserk_str = test.paserk.as_ref().expect("paserk required for fail test");
                let password = decode_password(test.password.as_ref().expect("password required"));

                let wrapped = PaserkSecretPw::<K4>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    // Only try to unwrap if parsing succeeded
                    // Extract params if available, otherwise use defaults (will likely fail)
                    let options = test.options.as_ref();
                    let params = Argon2Params {
                        memory_kib: options.and_then(|o| o.memlimit).map_or(65536, |m| m / 1024),
                        iterations: options.and_then(|o| o.opslimit).unwrap_or(2),
                        parallelism: 1,
                    };
                    let result = wrapped.try_unwrap(&password, params);
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed to unwrap",
                        test.name
                    );
                }
                // If parsing failed, that's also an expected failure - test passes
            } else {
                // Extract Argon2 parameters from test options
                let options = test.options.as_ref().expect("options required");
                let params = Argon2Params {
                    memory_kib: options.memlimit.expect("memlimit required") / 1024, // bytes to KiB
                    iterations: options.opslimit.expect("opslimit required"),
                    parallelism: 1,
                };
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped key required"))
                        .expect("valid hex");
                let password = decode_password(test.password.as_ref().expect("password required"));
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 64] = unwrapped_bytes
                    .try_into()
                    .expect("unwrapped key should be 64 bytes");
                let expected_key = PaserkSecret::<K4>::from(unwrapped_key);

                let wrapped = PaserkSecretPw::<K4>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&password, params)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    expected_key.as_bytes(),
                    "Test '{}' unwrap produced wrong key",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k4_seal_vectors() {
        let path = vectors_dir().join("k4.seal.json");
        let suite: TestVectorSuite<SealTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                let paserk_str = test.paserk.as_ref().expect("paserk required for fail test");
                let secret_key_bytes = hex_decode(
                    test.sealing_secret_key
                        .as_ref()
                        .expect("sealing secret key required"),
                )
                .expect("valid hex");
                let secret_key: [u8; 64] = secret_key_bytes
                    .try_into()
                    .expect("secret key should be 64 bytes");
                let secret_key = PaserkSecret::<K4>::from(secret_key);

                let sealed = PaserkSeal::<K4>::try_from(paserk_str.as_str());
                if let Ok(sealed) = sealed {
                    let result = sealed.try_unseal(&secret_key);
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed to unseal",
                        test.name
                    );
                }
            } else {
                let secret_key_bytes = hex_decode(
                    test.sealing_secret_key
                        .as_ref()
                        .expect("sealing secret key required"),
                )
                .expect("valid hex");
                let unsealed_bytes =
                    hex_decode(test.unsealed.as_ref().expect("unsealed key required"))
                        .expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let secret_key: [u8; 64] = secret_key_bytes
                    .try_into()
                    .expect("secret key should be 64 bytes");
                let unsealed_key: [u8; 32] = unsealed_bytes
                    .try_into()
                    .expect("unsealed key should be 32 bytes");

                let secret_key = PaserkSecret::<K4>::from(secret_key);
                let expected_key = PaserkLocal::<K4>::from(unsealed_key);

                let sealed = PaserkSeal::<K4>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' parsing failed: {e}", test.name));
                let recovered = sealed
                    .try_unseal(&secret_key)
                    .unwrap_or_else(|e| panic!("Test '{}' unseal failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    expected_key.as_bytes(),
                    "Test '{}' unseal produced wrong key",
                    test.name
                );
            }
        }
    }
}

// =============================================================================
// K2 Test Vectors
// =============================================================================

#[cfg(feature = "k2")]
mod k2_tests {
    use super::*;
    use paserk::core::operations::wrap::Pie;
    use paserk::core::types::{
        PaserkLocal, PaserkLocalId, PaserkLocalPw, PaserkLocalWrap, PaserkPublic, PaserkPublicId,
        PaserkSeal, PaserkSecret, PaserkSecretId, PaserkSecretPw, PaserkSecretWrap,
    };
    use paserk::K2;

    #[test]
    fn test_k2_local_vectors() {
        let path = vectors_dir().join("k2.local.json");
        let suite: TestVectorSuite<LocalTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                if let Some(paserk) = &test.paserk {
                    let result = PaserkLocal::<K2>::try_from(paserk.as_str());
                    assert!(
                        result.is_err(),
                        "Test '{}' should have failed but succeeded",
                        test.name
                    );
                }
            } else {
                let key_bytes =
                    hex_decode(test.key.as_ref().expect("key required")).expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let key_array: [u8; 32] = key_bytes.try_into().expect("32 bytes");
                let paserk = PaserkLocal::<K2>::from(key_array);

                assert_eq!(
                    paserk.to_string(),
                    *paserk_str,
                    "Test '{}' failed",
                    test.name
                );

                let parsed = PaserkLocal::<K2>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                assert_eq!(
                    parsed.as_bytes(),
                    &key_array,
                    "Test '{}' roundtrip failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_lid_vectors() {
        let path = vectors_dir().join("k2.lid.json");
        let suite: TestVectorSuite<LidTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                continue;
            }

            let key_bytes =
                hex_decode(test.key.as_ref().expect("key required")).expect("valid hex");
            let paserk_str = test.paserk.as_ref().expect("paserk required");

            let key_array: [u8; 32] = key_bytes.try_into().expect("32 bytes");
            let local_key = PaserkLocal::<K2>::from(key_array);
            let lid: PaserkLocalId<K2> = (&local_key).into();

            assert_eq!(lid.to_string(), *paserk_str, "Test '{}' failed", test.name);
        }
    }

    #[test]
    fn test_k2_public_vectors() {
        let path = vectors_dir().join("k2.public.json");
        let suite: TestVectorSuite<PublicTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                if let Some(paserk) = &test.paserk {
                    let result = PaserkPublic::<K2>::try_from(paserk.as_str());
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                let key_bytes =
                    hex_decode(test.key.as_ref().expect("key required")).expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let key_array: [u8; 32] = key_bytes.try_into().expect("32 bytes");
                let paserk = PaserkPublic::<K2>::from(key_array);

                assert_eq!(
                    paserk.to_string(),
                    *paserk_str,
                    "Test '{}' failed",
                    test.name
                );

                let parsed = PaserkPublic::<K2>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                assert_eq!(
                    parsed.as_bytes(),
                    &key_array,
                    "Test '{}' roundtrip failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_pid_vectors() {
        let path = vectors_dir().join("k2.pid.json");
        let suite: TestVectorSuite<PidTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                continue;
            }

            let key_bytes =
                hex_decode(test.key.as_ref().expect("key required")).expect("valid hex");
            let paserk_str = test.paserk.as_ref().expect("paserk required");

            let key_array: [u8; 32] = key_bytes.try_into().expect("32 bytes");
            let public_key = PaserkPublic::<K2>::from(key_array);
            let pid: PaserkPublicId<K2> = (&public_key).into();

            assert_eq!(pid.to_string(), *paserk_str, "Test '{}' failed", test.name);
        }
    }

    #[test]
    fn test_k2_secret_vectors() {
        let path = vectors_dir().join("k2.secret.json");
        let suite: TestVectorSuite<SecretTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                if let Some(paserk) = &test.paserk {
                    let result = PaserkSecret::<K2>::try_from(paserk.as_str());
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                let key_bytes =
                    hex_decode(test.key.as_ref().expect("key required")).expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let key_array: [u8; 64] = key_bytes.try_into().expect("64 bytes");
                let paserk = PaserkSecret::<K2>::from(key_array);

                assert_eq!(
                    paserk.to_string(),
                    *paserk_str,
                    "Test '{}' failed",
                    test.name
                );

                let parsed = PaserkSecret::<K2>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                assert_eq!(
                    parsed.as_bytes(),
                    &key_array,
                    "Test '{}' roundtrip failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_sid_vectors() {
        let path = vectors_dir().join("k2.sid.json");
        let suite: TestVectorSuite<SidTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                continue;
            }

            let key_bytes =
                hex_decode(test.key.as_ref().expect("key required")).expect("valid hex");
            let paserk_str = test.paserk.as_ref().expect("paserk required");

            let key_array: [u8; 64] = key_bytes.try_into().expect("64 bytes");
            let secret_key = PaserkSecret::<K2>::from(key_array);
            let sid: PaserkSecretId<K2> = (&secret_key).into();

            assert_eq!(sid.to_string(), *paserk_str, "Test '{}' failed", test.name);
        }
    }

    #[test]
    fn test_k2_local_wrap_pie_vectors() {
        let path = vectors_dir().join("k2.local-wrap.pie.json");
        let suite: TestVectorSuite<LocalWrapTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                let paserk_str = test.paserk.as_ref().expect("paserk required");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let wrapping_key: [u8; 32] = wrapping_key_bytes.try_into().expect("32 bytes");
                let wrapping_key = PaserkLocal::<K2>::from(wrapping_key);

                let wrapped = PaserkLocalWrap::<K2, Pie>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    let result = wrapped.try_unwrap(&wrapping_key);
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped required"))
                        .expect("valid hex");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 32] = unwrapped_bytes.try_into().expect("32 bytes");
                let wrapping_key: [u8; 32] = wrapping_key_bytes.try_into().expect("32 bytes");

                let key_to_wrap = PaserkLocal::<K2>::from(unwrapped_key);
                let wrapping_key = PaserkLocal::<K2>::from(wrapping_key);

                let wrapped = PaserkLocalWrap::<K2, Pie>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&wrapping_key)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    key_to_wrap.as_bytes(),
                    "Test '{}' failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_secret_wrap_pie_vectors() {
        let path = vectors_dir().join("k2.secret-wrap.pie.json");
        let suite: TestVectorSuite<SecretWrapTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                let paserk_str = test.paserk.as_ref().expect("paserk required");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let wrapping_key: [u8; 32] = wrapping_key_bytes.try_into().expect("32 bytes");
                let wrapping_key = PaserkLocal::<K2>::from(wrapping_key);

                let wrapped = PaserkSecretWrap::<K2, Pie>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    let result = wrapped.try_unwrap(&wrapping_key);
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped required"))
                        .expect("valid hex");
                let wrapping_key_bytes =
                    hex_decode(test.wrapping_key.as_ref().expect("wrapping key required"))
                        .expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 64] = unwrapped_bytes.try_into().expect("64 bytes");
                let wrapping_key: [u8; 32] = wrapping_key_bytes.try_into().expect("32 bytes");

                let key_to_wrap = PaserkSecret::<K2>::from(unwrapped_key);
                let wrapping_key = PaserkLocal::<K2>::from(wrapping_key);

                let wrapped = PaserkSecretWrap::<K2, Pie>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&wrapping_key)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    key_to_wrap.as_bytes(),
                    "Test '{}' failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_local_pw_vectors() {
        use paserk::Argon2Params;

        let path = vectors_dir().join("k2.local-pw.json");
        let suite: TestVectorSuite<LocalPwTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // For fail tests, the paserk might be for a wrong version
                // In that case, parsing should fail, so we don't need params
                let paserk_str = test.paserk.as_ref().expect("paserk required");
                let password = decode_password(test.password.as_ref().expect("password required"));

                let wrapped = PaserkLocalPw::<K2>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    // Only try to unwrap if parsing succeeded
                    let options = test.options.as_ref();
                    let params = Argon2Params {
                        memory_kib: options.and_then(|o| o.memlimit).map_or(65536, |m| m / 1024),
                        iterations: options.and_then(|o| o.opslimit).unwrap_or(2),
                        parallelism: 1,
                    };
                    let result = wrapped.try_unwrap(&password, params);
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                // Extract Argon2 parameters from test options
                let options = test.options.as_ref().expect("options required");
                let params = Argon2Params {
                    memory_kib: options.memlimit.expect("memlimit required") / 1024, // bytes to KiB
                    iterations: options.opslimit.expect("opslimit required"),
                    parallelism: 1,
                };
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped required"))
                        .expect("valid hex");
                let password = decode_password(test.password.as_ref().expect("password required"));
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 32] = unwrapped_bytes.try_into().expect("32 bytes");
                let expected_key = PaserkLocal::<K2>::from(unwrapped_key);

                let wrapped = PaserkLocalPw::<K2>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&password, params)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    expected_key.as_bytes(),
                    "Test '{}' failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_secret_pw_vectors() {
        use paserk::Argon2Params;

        let path = vectors_dir().join("k2.secret-pw.json");
        let suite: TestVectorSuite<SecretPwTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                // For fail tests, the paserk might be for a wrong version
                // In that case, parsing should fail, so we don't need params
                let paserk_str = test.paserk.as_ref().expect("paserk required");
                let password = decode_password(test.password.as_ref().expect("password required"));

                let wrapped = PaserkSecretPw::<K2>::try_from(paserk_str.as_str());
                if let Ok(wrapped) = wrapped {
                    // Only try to unwrap if parsing succeeded
                    let options = test.options.as_ref();
                    let params = Argon2Params {
                        memory_kib: options.and_then(|o| o.memlimit).map_or(65536, |m| m / 1024),
                        iterations: options.and_then(|o| o.opslimit).unwrap_or(2),
                        parallelism: 1,
                    };
                    let result = wrapped.try_unwrap(&password, params);
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                // Extract Argon2 parameters from test options
                let options = test.options.as_ref().expect("options required");
                let params = Argon2Params {
                    memory_kib: options.memlimit.expect("memlimit required") / 1024, // bytes to KiB
                    iterations: options.opslimit.expect("opslimit required"),
                    parallelism: 1,
                };
                let unwrapped_bytes =
                    hex_decode(test.unwrapped.as_ref().expect("unwrapped required"))
                        .expect("valid hex");
                let password = decode_password(test.password.as_ref().expect("password required"));
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let unwrapped_key: [u8; 64] = unwrapped_bytes.try_into().expect("64 bytes");
                let expected_key = PaserkSecret::<K2>::from(unwrapped_key);

                let wrapped = PaserkSecretPw::<K2>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                let recovered = wrapped
                    .try_unwrap(&password, params)
                    .unwrap_or_else(|e| panic!("Test '{}' unwrap failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    expected_key.as_bytes(),
                    "Test '{}' failed",
                    test.name
                );
            }
        }
    }

    #[test]
    fn test_k2_seal_vectors() {
        let path = vectors_dir().join("k2.seal.json");
        let suite: TestVectorSuite<SealTestVector> =
            load_vectors(path.to_str().expect("valid path"));

        for test in suite.tests {
            if test.expect_fail {
                let paserk_str = test.paserk.as_ref().expect("paserk required");
                let secret_key_bytes = hex_decode(
                    test.sealing_secret_key
                        .as_ref()
                        .expect("sealing secret key required"),
                )
                .expect("valid hex");
                let secret_key: [u8; 64] = secret_key_bytes.try_into().expect("64 bytes");
                let secret_key = PaserkSecret::<K2>::from(secret_key);

                let sealed = PaserkSeal::<K2>::try_from(paserk_str.as_str());
                if let Ok(sealed) = sealed {
                    let result = sealed.try_unseal(&secret_key);
                    assert!(result.is_err(), "Test '{}' should have failed", test.name);
                }
            } else {
                let secret_key_bytes = hex_decode(
                    test.sealing_secret_key
                        .as_ref()
                        .expect("sealing secret key required"),
                )
                .expect("valid hex");
                let unsealed_bytes = hex_decode(test.unsealed.as_ref().expect("unsealed required"))
                    .expect("valid hex");
                let paserk_str = test.paserk.as_ref().expect("paserk required");

                let secret_key: [u8; 64] = secret_key_bytes.try_into().expect("64 bytes");
                let unsealed_key: [u8; 32] = unsealed_bytes.try_into().expect("32 bytes");

                let secret_key = PaserkSecret::<K2>::from(secret_key);
                let expected_key = PaserkLocal::<K2>::from(unsealed_key);

                let sealed = PaserkSeal::<K2>::try_from(paserk_str.as_str())
                    .unwrap_or_else(|e| panic!("Test '{}' failed: {e}", test.name));
                let recovered = sealed
                    .try_unseal(&secret_key)
                    .unwrap_or_else(|e| panic!("Test '{}' unseal failed: {e}", test.name));

                assert_eq!(
                    recovered.as_bytes(),
                    expected_key.as_bytes(),
                    "Test '{}' failed",
                    test.name
                );
            }
        }
    }
}
