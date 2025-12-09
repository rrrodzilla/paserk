# paserk

[![Crates.io](https://img.shields.io/crates/v/paserk.svg)](https://crates.io/crates/paserk) [![Documentation](https://docs.rs/paserk/badge.svg)](https://docs.rs/paserk) [![License](https://img.shields.io/crates/l/paserk.svg)](https://github.com/rrrodzilla/paserk#license) [![MSRV](https://img.shields.io/badge/MSRV-1.75.0-blue)](https://github.com/rrrodzilla/paserk)

Platform-Agnostic Serialized Keys (PASERK) for PASETO in Rust.

PASERK is a standard format for serializing keys used with [PASETO](https://paseto.io) tokens. This crate provides a type-safe, idiomatic Rust implementation of the [PASERK specification](https://github.com/paseto-standard/paserk).

## Features

- **Full PASERK specification support** - All 11 PASERK types across all 4 versions (K1-K4)
- **Type-safe API** - Version markers prevent mixing keys from different PASETO versions
- **Security-first design** - Keys are zeroized on drop, no unsafe code, constant-time comparisons
- **Flexible feature flags** - Enable only the versions you need to minimize dependencies
- **Ergonomic builders** - Fluent APIs for password-based key wrapping with preset security profiles

## Quick Start

Add `paserk` to your `Cargo.toml`:

```toml
[dependencies]
paserk = "0.4"
```

By default, K4 (the recommended version) and the ergonomic `prelude` are enabled. See [Feature Flags](#feature-flags) for other options.

### Basic Usage

```rust
use paserk::prelude::*;

// Create a symmetric key from raw bytes
let key = PaserkLocal::<K4>::from([0x42u8; 32]);

// Serialize to PASERK format
let paserk_string = key.to_string();
assert!(paserk_string.starts_with("k4.local."));

// Parse a PASERK string
let parsed: PaserkLocal<K4> = paserk_string.parse().unwrap();

// Compute a key identifier
let key_id = PaserkLocalId::<K4>::from(&key);
assert!(key_id.to_string().starts_with("k4.lid."));
```

### Password-Based Key Wrapping

Protect keys with a password using Argon2id (K2/K4) or PBKDF2 (K1/K3):

```rust
use paserk::prelude::*;

let key = PaserkLocal::<K4>::from([0x42u8; 32]);

// Wrap with preset security profile
let wrapped = LocalPwBuilder::<K4>::moderate()
    .try_wrap(&key, b"my-secure-password")?;

// Serialize the wrapped key
let wrapped_string = wrapped.to_string();
assert!(wrapped_string.starts_with("k4.local-pw."));

// Later, unwrap the key
let unwrapped = wrapped.try_unwrap(b"my-secure-password")?;
```

### Key Wrapping with Another Key

Wrap a key using PIE (Platform-Independent Encryption):

```rust
use paserk::prelude::*;

let key_to_wrap = PaserkLocal::<K4>::from([0x42u8; 32]);
let wrapping_key = PaserkLocal::<K4>::from([0x00u8; 32]);

// Wrap the key
let wrapped = PaserkLocalWrap::<K4, Pie>::wrap(&key_to_wrap, &wrapping_key);
assert!(wrapped.to_string().starts_with("k4.local-wrap.pie."));

// Unwrap the key
let unwrapped = wrapped.try_unwrap(&wrapping_key)?;
```

### Public Key Encryption (Seal)

Encrypt a symmetric key to a public key:

```rust
use paserk::prelude::*;

let symmetric_key = PaserkLocal::<K4>::from([0x42u8; 32]);

// Generate or load a secret key (contains both secret and public parts)
let secret_key = PaserkSecret::<K4>::from([0u8; 64]);

// Seal the symmetric key to the public key
let sealed = PaserkSeal::<K4>::seal(&symmetric_key, &secret_key);
assert!(sealed.to_string().starts_with("k4.seal."));

// Unseal with the secret key
let unsealed = sealed.try_unseal(&secret_key)?;
```

## PASERK Types

| Type | Format | Description |
|------|--------|-------------|
| `local` | `k{v}.local.{data}` | Symmetric encryption key |
| `public` | `k{v}.public.{data}` | Public verification key |
| `secret` | `k{v}.secret.{data}` | Secret signing key |
| `lid` | `k{v}.lid.{data}` | Local key identifier |
| `pid` | `k{v}.pid.{data}` | Public key identifier |
| `sid` | `k{v}.sid.{data}` | Secret key identifier |
| `local-wrap` | `k{v}.local-wrap.pie.{data}` | PIE-wrapped symmetric key |
| `secret-wrap` | `k{v}.secret-wrap.pie.{data}` | PIE-wrapped secret key |
| `local-pw` | `k{v}.local-pw.{data}` | Password-wrapped symmetric key |
| `secret-pw` | `k{v}.secret-pw.{data}` | Password-wrapped secret key |
| `seal` | `k{v}.seal.{data}` | PKE-encrypted symmetric key |

## Versions

PASERK supports four versions corresponding to PASETO versions:

| Version | Algorithms | Use Case |
|---------|------------|----------|
| **K1** | RSA-4096, AES-256-CTR, HMAC-SHA384, PBKDF2 | NIST compliance (legacy) |
| **K2** | Ed25519, XChaCha20, BLAKE2b, Argon2id | Sodium-based (PASETO V2) |
| **K3** | P-384, AES-256-CTR, HMAC-SHA384, PBKDF2 | NIST compliance (modern) |
| **K4** | Ed25519, XChaCha20, BLAKE2b, Argon2id | **Recommended for new applications** |

### Version Compatibility

| Type | K1 | K2 | K3 | K4 |
|------|:--:|:--:|:--:|:--:|
| `local` | ✓ | ✓ | ✓ | ✓ |
| `public` | ✓ | ✓ | ✓ | ✓ |
| `secret` | — | ✓ | ✓ | ✓ |
| `lid` | ✓ | ✓ | ✓ | ✓ |
| `pid` | ✓ | ✓ | ✓ | ✓ |
| `sid` | — | ✓ | ✓ | ✓ |
| `local-wrap` | ✓ | ✓ | ✓ | ✓ |
| `secret-wrap` | — | ✓ | ✓ | ✓ |
| `local-pw` | ✓ | ✓ | ✓ | ✓ |
| `secret-pw` | — | ✓ | ✓ | ✓ |
| `seal` | ✓ | ✓ | ✓ | ✓ |

Note: K1 uses RSA which has no separate secret key type in PASETO V1.

## Feature Flags

Enable specific PASERK versions based on your needs:

```toml
# K4 + prelude (default, recommended for new applications)
paserk = "0.4"

# Multiple specific versions
paserk = { version = "0.4", features = ["k2", "k4"] }

# All versions
paserk = { version = "0.4", features = ["all-versions"] }

# Minimal (no prelude, for power users)
paserk = { version = "0.4", default-features = false, features = ["k4"] }
```

| Feature | Description | Dependencies Added |
|---------|-------------|--------------------|
| `k1` | NIST original (RSA-based) | sha2, hmac, aes, ctr, pbkdf2, rsa |
| `k2` | Sodium original | blake2, chacha20, argon2, x25519-dalek, ed25519-dalek |
| `k3` | NIST modern (P-384-based) | sha2, hmac, aes, ctr, pbkdf2, p384 |
| `k4` | Sodium modern (default) | blake2, chacha20, argon2, x25519-dalek, ed25519-dalek |
| `prelude` | Ergonomic imports and builders (default) | — |
| `all-versions` | Enable K1, K2, K3, K4 | All of the above |

### The Prelude

The `prelude` module provides a single import for common usage:

```rust
use paserk::prelude::*;
```

This gives you access to:

- **All key types**: `PaserkLocal`, `PaserkPublic`, `PaserkSecret`
- **Key identifiers**: `PaserkLocalId`, `PaserkPublicId`, `PaserkSecretId`
- **Wrapping types**: `PaserkLocalWrap`, `PaserkSecretWrap`, `PaserkLocalPw`, `PaserkSecretPw`, `PaserkSeal`
- **Version markers**: `K1`, `K2`, `K3`, `K4`
- **Fluent builders**: `LocalPwBuilder`, `SecretPwBuilder` with preset security profiles
- **Error types**: `PaserkError`, `PaserkResult`

## Cryptographic Operations

### Key Wrapping (PIE Protocol)

| Version | Encryption | Authentication |
|---------|------------|----------------|
| K1/K3 | AES-256-CTR | HMAC-SHA384 (48-byte tag) |
| K2/K4 | XChaCha20 | BLAKE2b (32-byte tag) |

### Password-Based Key Wrapping (PBKW)

| Version | KDF | Encryption | Authentication |
|---------|-----|------------|----------------|
| K1/K3 | PBKDF2-SHA384 | AES-256-CTR | HMAC-SHA384 |
| K2/K4 | Argon2id | XChaCha20 | BLAKE2b |

**Security Profiles** (for K2/K4 Argon2id):

| Profile | Memory | Iterations | Use Case |
|---------|--------|------------|----------|
| `interactive()` | 64 MiB | 2 | Online authentication |
| `moderate()` | 256 MiB | 3 | Default, balanced security |
| `sensitive()` | 1 GiB | 4 | High-value secrets |

### Public Key Encryption (Seal)

| Version | Key Exchange | Encryption | Authentication |
|---------|--------------|------------|----------------|
| K1 | RSA-4096 KEM | AES-256-CTR | HMAC-SHA384 |
| K2/K4 | X25519 ECDH | XChaCha20 | BLAKE2b |
| K3 | P-384 ECDH | AES-256-CTR | HMAC-SHA384 |

## Security

This crate prioritizes security:

- **Memory safety**: All key material is zeroized on drop using the `zeroize` crate
- **No unsafe code**: Enforced via `#![forbid(unsafe_code)]`
- **Constant-time operations**: Secret comparisons use the `subtle` crate
- **Redacted debug output**: `Debug` implementations hide sensitive key material
- **Authenticated encryption**: All wrapping operations use AEAD-equivalent constructions
- **Strict lints**: `unwrap`, `expect`, and `panic` are denied

## API Documentation

Full API documentation is available on [docs.rs](https://docs.rs/paserk).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [PASETO](https://paseto.io) - Platform-Agnostic Security Tokens
- [PASERK Specification](https://github.com/paseto-standard/paserk) - The official PASERK specification
